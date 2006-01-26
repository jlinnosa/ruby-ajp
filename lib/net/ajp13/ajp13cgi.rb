require 'net/ajp13'
require 'cgi'
require 'forwardable'

# The adapter to adapt Net::AJP13::Request and Net::AJP13::Response into
# CGI's interface.
class Net::AJP13::AJP13CGI
  include ::CGI::QueryExtension
  extend Forwardable

  def initialize(req)
    @req = req
    if req.method == "POST" and
      %r|\Amultipart/form-data.*boundary=\"?([^\";,]+)\"?|n.match(req['content-type']) then
      boundary = $1.dup
      @multipart = true
      @params = read_multipart(boundary, req.content_length)
    elsif req.body_stream and 
      req['content-type'] == 'application/x-www-form-urlencoded'
      @multipart = false
      @params = CGI::parse(req.body = req.body_stream.read)
      req.body_stream = nil
    elsif qs = query_string
      @multipart = false
      @params = CGI::parse(qs)
    else
      @multipart = false
      @params = {}
    end

    @env_table = self.method(:env)
    class << @env_table
      def include?(key)
        call(key).nil?
      end
      alias :key? :include?
    end
    @cookies = CGI::Cookie::parse(req['cookie'])
  end

  # Created AJP13::Response object.
  attr_reader :response

  MESSAGE_TO_STATUS = {
    :OK                  => [200, "OK"],
    :PARTIAL_CONTENT     => [206, "Partial Content"],
    :MULTIPLE_CHOICES    => [300, "Multiple Choices"],
    :MOVED               => [301, "Moved Permanently"],
    :REDIRECT            => [302, "Found"],
    :NOT_MODIFIED        => [304, "Not Modified"],
    :BAD_REQUEST         => [400, "Bad Request"],
    :AUTH_REQUIRED       => [401, "Authorization Required"],
    :FORBIDDEN           => [403, "Forbidden"],
    :NOT_FOUND           => [404, "Not Found"],
    :METHOD_NOT_ALLOWED  => [405, "Method Not Allowed"],
    :NOT_ACCEPTABLE      => [406, "Not Acceptable"],
    :LENGTH_REQUIRED     => [411, "Length Required"],
    :PRECONDITION_FAILED => [412, "Rrecondition Failed"],
    :SERVER_ERROR        => [500, "Internal Server Error"],
    :NOT_IMPLEMENTED     => [501, "Method Not Implemented"],
    :BAD_GATEWAY         => [502, "Bad Gateway"],
    :VARIANT_ALSO_VARIES => [506, "Variant Also Negotiates"],
  }.freeze

  def header(arg = "text/html")
    if arg.kind_of? String
      @response = Net::AJP13::Response.new(200)
      @response['content-type'] = arg
    elsif arg.respond_to?(:each) and arg.respond_to?(:[])
      if status = arg['status'] 
        raise ArgumentError, "Unrecognized status line format: #{status}" unless          /\A(?:([0-9]{3}) )?(\w+)\Z/ =~ status
        status_line = $1 ? [$1.to_i, $2] : MESSAGE_TO_STATUS[$2.to_sym]
	raise ArgumentError, "Unrecognized status line: #{status}" unless status_line
	@response = Net::AJP13::Response.new(status_line[0], :reason_phrase => status_line[1])
      else
        @response = Net::AJP13::Response.new(200)
      end
      type = nil; charset = nil
      arg.each do |name, value|
        case name.downcase
	when 'nph', 'status'
	  # do nothing
	when "type"
	  type = value
	when "charset"
	  charset = value
	when 'length'
	  @response['content-length'] = value.to_s
	when 'language'
	  @response['content-language'] = value
	when 'cookie'
	  case value
	  when String
	    @respose.add_header('set-cookie', value)
	  when Array, Hash
	    value.each {|val| @response.add_header('set-cookie', val.to_s) }
	  end
        else
	  @response[name] = value
	end
      end
      type = 'text/html' unless type
      @response['content-type'] = charset ? ("%s; charset=%s" % [type, charset]) : type
    else
      raise ArgumentError, "argument is not a String nor Hash"
    end
  end


  def output(arg = 'text/html')
    content = yield
    header(arg)
    @response['content-length'] ||= content.length
    unless content.nil? or @request.method == 'HEAD'
      @response.body = content
    end
  end

  # Method object that contains #env
  attr_reader :env_table

  # Simulates environment variable table that Common Gateway Interface defines.
  def env(name)
    name = name.downcase
    key = name.to_sym
    if [
      :auth_type, :content_length, :content_type, :gateway_interface,
      :path_info, :path_translated, :query_string, :remote_addr, :remote_host,
      :remote_ident, :remote_user, :request_method, :request_url, :script_name,
      :server_name, :server_port, :server_protocol, :server_software
    ].include?(key) then
      return __send__(key)
    elsif /\Ahttp_(\w+)\Z/ =~ name
      return @req[$1.tr('_', '-')]
    else
      return nil
    end
  end
  private :env

  def_delegators :@req, 
    :content_length, :remote_addr, :remote_host, :server_name, :server_port

  [
    :auth_type, 
   # :path_info, 
    :path_translated,
    :remote_ident, :remote_user, 
    :script_name, :server_software
  ].each do |attr_name|
    define_method(attr_name) do
      val = @req.get_attributes(attr_name.to_s)
      val and val[0]
    end
  end

  def content_type
    @req['content-type']
  end

  def gateway_interface
    'AJP/1.3'
  end

  def path_info
    #val = @req.get_attributes('path_info')
    #val && val[0] or @req.path
    @req.path
  end

  def query_string
    qs = @req.get_attributes('query_string')
    qs and qs.join('&')
  end

  def request_method
    @req.method
  end

  def request_url
    @req.path
  end

  def server_protocol
    @req.protocol
  end
end
