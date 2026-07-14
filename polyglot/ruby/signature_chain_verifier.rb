require 'openssl'
require 'base64'
require 'digest/sha256'
require 'json'
require 'time'

# ============== Configuration Defaults ==============

module Otaverify
  DEFAULT_CONFIG = {
    root_cert_path: '/etc/otaverify/root.pem',
    chain_file_path: '/etc/otaverify/chain.json',
    update_package_path: '/tmp/update.bin',
    delta_patch_path: nil,
    timestamp_window_seconds: 300,      # 5 minutes tolerance
    max_counter_jump: 100,              # Allow up to 100 counter jumps
    min_signature_bits: 2048,           # Minimum RSA key size
    expected_root_cn: 'OTA Root CA',
    verify_chain_order: true,          # Enforce strict order verification
  }.freeze

  class Config < DEFAULT_CONFIG
    def self.merged(config_hash = {})
      defaults = DEFAULT_CONFIG.dup
      config_hash.each { |k, v| defaults[k] = v } if k.is_a?(String) || k.is_a?(Symbol)
      defaults.merge!(config_hash.transform_keys(&:to_s))
      defaults
    end

    def self.from_file(path)
      content = File.read(path).strip
      return DEFAULT_CONFIG unless content.empty?
      
      begin
        json = JSON.parse(content)
        merged(DEFAULT_CONFIG, json)
      rescue JSON::ParserError
        DEFAULT_CONFIG
      end
    end
  end

  # ============== Certificate Entry ==============

  class CertificateEntry
    attr_reader :subject, :issuer, :serial, :not_before, :not_after, 
                :public_key, :signature_data, :timestamp, :counter
    
    def initialize(subject: nil, issuer: nil, serial: nil, not_before: Time.now,
                   not_after: Time.now + 365.days, public_key: nil, signature_data: nil,
                   timestamp: Time.now, counter: 0)
      @subject = subject || ''
      @issuer = issuer || ''
      @serial = serial || '0'
      @not_before = not_before
      @not_after = not_after
      @public_key = public_key
      @signature_data = signature_data
      @timestamp = timestamp
      @counter = counter
    end

    def valid_time?(now)
      now >= @not_before && now <= @not_after
    end

    def time_skew_seconds(now)
      if !valid_time?(now)
        if now < @not_before
          (@not_before - now).to_i
        else
          (now - @not_after).to_i
        end
      else
        0
      end
    end

    def valid_counter?(expected, max_jump: Otaverify::DEFAULT_CONFIG[:max_counter_jump])
      delta = expected - @counter
      return true if delta.abs <= max_jump
      
      { status: :counter_skew, 
        message: "Counter jump of #{delta} exceeds max (#{max_jump})",
        delta: delta }
    end

    def to_json(options = {})
      {
        subject: @subject,
        issuer: @issuer,
        serial: @serial,
        not_before: @not_before.iso8601,
        not_after: @not_after.iso8601,
        timestamp: @timestamp.iso8601,
        counter: @counter,
      }.to_json(options)
    end

    def self.from_json(json_str)
      data = JSON.parse(json_str)
      new(
        subject: data['subject'],
        issuer: data['issuer'],
        serial: data['serial'],
        not_before: Time.iso8601(data['not_before']),
        not_after: Time.iso8601(data['not_after']),
        timestamp: Time.iso8601(data['timestamp']),
        counter: data['counter'] || 0,
      )
    end

    def self.from_pem(pem_data)
      cert = OpenSSL::X509::Certificate.new(pem_data)
      new(
        subject: cert.subject.to_a.first[1].to_s.strip,
        issuer: cert.issuer.to_a.first[1].to_s.strip,
        serial: cert.serial.to_s.rjust(2, '0'),
        not_before: cert.not_before,
        not_after: cert.not_after,
        public_key: cert.public_key,
      )
    end
  end

  # ============== Signature Chain Node ==============

  class ChainNode
    attr_reader :cert_entry, :previous_hash, :data_hash, :signature
    
    def initialize(cert_entry:, previous_hash: nil, data_hash: nil, signature: nil)
      @cert_entry = cert_entry
      @previous_hash = previous_hash || ''
      @data_hash = data_hash || ''
      @signature = signature
    end

    def compute_previous_hash(previous_node)
      if previous_node
        prev_data = "#{previous_node.cert_entry.to_json}\n" + 
                    "prev_hash=#{previous_node.previous_hash}\n"
        Digest::SHA256.hexdigest(prev_data)
      else
        'ROOT'
      end
    end

    def compute_data_hash(data)
      Digest::SHA256.hexdigest(data)
    end

    def verify_signature(previous_hash, data_hash, public_key)
      combined = "prev_hash=#{previous_hash}\ndata_hash=#{data_hash}"
      
      begin
        digest = OpenSSL::Digest.new('SHA256')
        signed_data = "#{combined}\n"
        
        if public_key.is_a?(OpenSSL::PKey::RSA)
          rsa = public_key
        else
          rsa = OpenSSL::PKey::RSA.new(public_key.to_s)
        end
        
        expected = rsa.verify(digest, signed_data, @signature)
        !expected.nil?
      rescue OpenSSL::PKey::RSAError => e
        false
      end
    end

    def to_json(options = {})
      {
        cert: @cert_entry.to_json,
        previous_hash: @previous_hash,
        data_hash: @data_hash,
        signature: Base64.encode64(@signature),
      }.to_json(options)
    end

    def self.from_json(json_str)
      data = JSON.parse(json_str)
      
      cert_entry = CertificateEntry.from_json(data['cert'])
      
      new(
        cert_entry: cert_entry,
        previous_hash: data['previous_hash'],
        data_hash: data['data_hash'],
        signature: Base64.decode64(data['signature']),
      )
    end
  end

  # ============== Verification Result ==============

  class VerificationResult
    attr_reader :status, :timestamp, :root_valid, :chain_valid, 
                :delta_valid, :warnings, :errors
    
    def initialize(status: :pending, timestamp: Time.now)
      @status = status
      @timestamp = timestamp
      @root_valid = nil
      @chain_valid = nil
      @delta_valid = nil
      @warnings = []
      @errors = []
    end

    def success?
      [:success, :partial_success].include?(@status)
    end

    def failure?
      [:failure, :root_failure, :chain_failure, :delta_failure].include?(@status)
    end

    def partial?
      @status == :partial_success
    end

    def with_error(message:, level: :error)
      if level == :error
        @errors << message
        @status = :failure unless [:success, :partial_success].include?(@status)
      else
        @warnings << message
      end
      
      self
    end

    def with_root_valid(valid:)
      @root_valid = valid
      if !valid && @status != :pending
        @status = :root_failure
      elsif valid && [:failure, :partial_success].include?(@status)
        @status = :success
      end
      
      self
    end

    def with_chain_valid(valid:)
      @chain_valid = valid
      if !valid && @status != :pending
        @status = :chain_failure
      elsif valid && [:failure, :root_failure].include?(@status)
        @status = :success
      end
      
      self
    end

    def with_delta_valid(valid:)
      @delta_valid = valid
      if !valid && @status != :pending
        @status = :delta_failure
      elsif valid && [:failure, :root_failure, :chain_failure].include?(@status)
        @status = :success
      end
      
      self
    end

    def to_json(options = {})
      {
        status: @status.to_s,
        timestamp: @timestamp.iso8601,
        root_valid: @root_valid,
        chain_valid: @chain_valid,
        delta_valid: @delta_valid,
        warnings: @warnings,
        errors: @errors,
      }.to_json(options)
    end

    def to_report
      lines = []
      
      header = "OTA Signature Chain Verification Report"
      lines << "=" * 50
      lines << header
      lines << "=" * 50
      
      status_line = case @status
                    when :success
                      "[SUCCESS]"
                    when :root_failure
                      "[ROOT FAILURE]"
                    when :chain_failure
                      "[CHAIN FAILURE]"
                    when :delta_failure
                      "[DELTA FAILURE]"
                    when :partial_success
                      "[PARTIAL SUCCESS]"
                    else
                      "[PENDING]"
                    end
      lines << ""
      lines << "Status: #{status_line}"
      lines << "Verified at: #{@timestamp.iso8601}"
      
      if @root_valid != nil
        root_str = @root_valid ? "  Root Certificate: VALID" : "  Root Certificate: INVALID"
        lines << root_str
      end
      
      if @chain_valid != nil
        chain_str = @chain_valid ? "  Chain Integrity: VALID" : "  Chain Integrity: INVALID"
        lines << chain_str
      end
      
      if @delta_valid != nil
        delta_str = @delta_valid ? "  Delta Patch: VALID" : "  Delta Patch: INVALID"
        lines << delta_str
      end
      
      lines << ""
      
      if @warnings.any?
        lines << "Warnings:"
        @warnings.each { |w| lines << "  - #{w}" }
        lines << ""
      end
      
      if @errors.any?
        lines << "Errors:"
        @errors.each { |e| lines << "  - #{e}" }
        lines << ""
      end
      
      lines << "=" * 50
      lines << "End of Report"
      lines << "=" * 50
      
      lines.join("\n")
    end

    def self.from_json(json_str)
      data = JSON.parse(json_str)
      new(
        status: data['status'],
        timestamp: Time.iso8601(data['timestamp']),
        root_valid: data['root_valid'],
        chain_valid: data['chain_valid'],
        delta_valid: data['delta_valid'],
        warnings: Array(data['warnings']),
        errors: Array(data['errors']),
      )
    end
  end

  # ============== Signature Chain Verifier (Main Class) ==============

  class SignatureChainVerifier
    include Otaverify::Config
    
    attr_reader :config, :result
    
    def initialize(config_hash = {})
      @config = Config.merged(config_hash)
      @result = VerificationResult.new
    end

    # Main verification entry point
    def verify!(package_path: nil, chain_data: nil, delta_patch_path: nil, 
                root_cert_path: nil, config_hash: {})
      
      package_path ||= @config[:update_package_path]
      delta_patch_path ||= @config[:delta_patch_path]
      root_cert_path ||= @config[:root_cert_path]
      
      # Load configuration if provided
      if config_hash.any?
        @config = Config.merged(@config, config_hash)
      end
      
      # Build chain from JSON data or extract from package
      chain_data ||= extract_chain_from_package(package_path)
      
      # Verify root certificate first
      verify_root(root_cert_path: root_cert_path) do |root_valid|
        @result.with_root_valid(valid: root_valid)
        
        if !root_valid && @result.root_valid == false
          return @result
        end
      end
      
      # Verify signature chain
      verify_chain(chain_data, package_path) do |chain_valid, nodes|
        @result.with_chain_valid(valid: chain_valid)
        
        if !chain_valid && @result.chain_valid == false
          return @result
        end
        
        # If we have nodes, verify each one's signature
        verify_node_signatures(nodes)
      end
      
      # Verify delta patch if present
      if delta_patch_path
        verify_delta(delta_patch_path, package_path) do |delta_valid|
          @result.with_delta_valid(valid: delta_valid)
        end
      end
      
      @result
    rescue => e
      @result = VerificationResult.new(status: :failure).with_error(
        message: "Unexpected error during verification",
        level: :error,
      ).with_error(message: e.message, level: :error)
      
      @result
    end

    private

    def extract_chain_from_package(package_path)
      # Try to read chain from embedded JSON in package header
      begin
        file = File.open(package_path, 'rb')
        
        # Read first 4KB as potential metadata
        header = file.read(4096).strip
        
        if header.start_with?('{')
          data = JSON.parse(header)
          
          if data['version'] == 1 || data['format'] == 'otaverify-v1'
            # Extract chain nodes from the parsed data
            nodes = []
            
            if data['nodes'].is_a?(Array)
              data['nodes'].each do |node_data|
                node = ChainNode.from_json(node_data.to_json)
                nodes << node
              end
            end
            
            return { raw: header, nodes: nodes }
          end
        end
        
      rescue => e
        # Fall through to default behavior
      end
      
      # Default: expect chain in a separate file or JSON field
      { raw: '', nodes: [] }
    end

    def verify_root(root_cert_path:)
      yield true if root_cert_path.nil? || File.exist?(root_cert_path)
      
      cert = OpenSSL::X509::Certificate.new(File.read(root_cert_path))
      
      # Verify key size
      key_size = cert.public_key.to_s.bytesize / 2
      
      @result.with_error(
        message: "Root certificate key too small (#{key_size} bits, min #{@config[:min_signature_bits]})",
        level: :warning,
      ) if key_size < @config[:min_signature_bits]
      
      # Verify CN matches expected
      cn = cert.subject.to_a.find { |a| a[0].to_s == 'CN' }
      if cn && !cn[1].to_s.strip.start_with?(@config[:expected_root_cn])
        @result.with_error(
          message: "Root CN mismatch (expected #{@config[:expected_root_cn]}, got #{cn[1]})",
          level: :warning,
        )
      end
      
      true
    end

    def verify_chain(chain_data, package_path)
      nodes = chain_data[:nodes] || []
      
      if nodes.empty?
        @result.with_error(
          message: "No signature nodes found in chain data",
          level: :error,
        )
        
        return false
      end
      
      # Verify each node in order
      prev_hash = 'ROOT'
      
      nodes.each_with_index do |node_data, index|
        node = ChainNode.from_json(node_data.to_json)
        
        expected_prev = if index == 0
                         'ROOT'
                       else
                         nodes[index - 1].previous_hash
                       end
        
        computed_prev = node.compute_previous_hash(nodes[index - 1])
        
        unless computed_prev == expected_prev
          @result.with_error(
            message: "Node #{index} previous hash mismatch",
            level: :error,
          )
          
          return false
        end
        
        # Verify signature against previous and data hashes
        if !node.verify_signature(expected_prev, node.data_hash, node.cert_entry.public_key)
          @result.with_error(
            message: "Node #{index} signature verification failed",