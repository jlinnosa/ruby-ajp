# = Ruby/AJP
# An implementation of AJP(Apache Jserv Protocol) 1.3 in Ruby, 
# based on http://tomcat.apache.org/connectors-doc/common/ajpv13a.html.
#
# [Net::AJP13::Client] provides high-level API to implement AJP clients.
#                      The interface of the client-side library is similar to
#                      net/http.
#                      see ajp13client.rb[link:files/lib/net/ajp13client_rb.html]
#                      for more detail.
# [Net::AJP13::Server] provides high-level API to implement AJP servers.
#                      see ajp13server.rb[link:files/lib/net/ajp13server_rb.html]
#                      for more detail.
#
# Author:: Yugui (mailto:yugui@yugui.sakura.ne.jp)
# Copyright:: Copyright (c) 2005-2006 Yugui
# License:: LGPL
#           
#           This library is free software; you can redistribute it and/or
#           modify it under the terms of the GNU Lesser General Public
#           License as published by the Free Software Foundation; version 2.1
#           of the License any later version.
#
#           This library is distributed in the hope that it will be useful,
#           but WITHOUT ANY WARRANTY; without even the implied warranty of
#           MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#           Lesser General Public License for more details.
#
#           You should have received a copy of the GNU Lesser General Public
#           License along with this library; if not, write to the Free Software
#           Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, 
#           MA  02110-1301  USA
#

require 'net/http'

# :stopdoc:
module Net; end
# :startdoc:

module Net::AJP13
  module Constants 
    # default AJP port
    DEFAULT_PORT = 8009

    # :stopdoc:
    FORWARD_REQUEST = 0x02
    SHUTDOWN = 0x07
    PING = 0x08
    CPING = 0x0A

    SEND_BODY_CHUNK = 0x03
    SEND_HEADERS = 0x04
    END_RESPONSE = 0x05
    GET_BODY_CHUNK = 0x06
    CPONG_REPLY = 0x09

    MAX_PACKET_SIZE = 8 * 1024 - 4  # limitaion of Jakarta's implementation
    MAX_BODY_CHUNK_SIZE = MAX_PACKET_SIZE - 2
    # :startdoc:
  end
end

#
# Represents AJP1.3 Request.
#
# Mixes int the Net::HTTPHeader module
# 
class Net::AJP13::Request
  include Net::HTTPHeader
  include Net::AJP13::Constants

  # :stopdoc:

  # maps HTTP/WebDAV method into its 16bit code
  REQUEST_METHOD_CODES = {
    :OPTIONS => 1, :GET => 2, :HEAD => 3, :POST => 4,
    :PUT => 5, :DELETE => 6, :TRACE => 7, :PROPFIND => 8,
    :PROPPATCH => 9, :MKCOL => 10, :COPY => 11, :MOVE => 12,
    :LOCK => 13, :UNLOCK => 14, :ACL => 15, :REPORT => 16,
    'VERSION-CONTROL'.intern => 17, :CHECKIN => 18, :CHECKOUT => 19,
    :UNCHECKOUT => 20, :SEARCH => 21
  }.freeze

  # Maps core HTTP headers into its 16bit code
  SC_REQ_HEADER_NAMES = {
    'accept' => 0xA001, 'accept-charset' => 0xA002,
    'accept-encoding' => 0xA003, 'accept-language' => 0xA004,
    'authorization' => 0xA005, 'connection' => 0xA006,
    'content-type' => 0xA007, 'content-length' => 0xA008,
    'cookie' => 0xA009, 'cookie2' => 0xA00A,
    'host' => 0xA00B, 'pragma' => 0xA00C,
    'referer' => 0xA00D, 'user_agent' => 0xA00E
  }.freeze
  SC_REQ_HEADER_NAMES.each_key {|k| k.freeze}

  SC_A_REQ_ATTRIBUTE = 0xA0
  # Maps request attribute names into their codes
  SC_A_NAMES = {
    :context => 0x01, 
    :servlet_path => 0x02,
    :remote_user => 0x03, 
    :auth_type => 0x04,
    :query_string => 0x05,
    :jvm_route => 0x06,
    :ssl_cert => 0x07,
    :ssl_cipher => 0x08,
    :ssl_session => 0x09,
    :req_attribute => SC_A_REQ_ATTRIBUTE,
    :ssl_key_size => 0x0B
  }.freeze

  # The termination byte of AJP request packet.
  REQUEST_TERMINATOR = 0xFF

  # :startdoc:

  #
  # Creates a AJP13 request object.
  # +path+:: path to request
  #
  def initialize(path, init_header = nil)
    @method = self.class::METHOD
    @request_has_body = self.class::REQUEST_HAS_BODY
    @response_has_body = self.class::RESPONSE_HAS_BODY
    @path, qs = path.split(/\?/, 2)
    initialize_http_header init_header
    @attributes = {}
    add_attribute('query_string', qs) if qs

    @is_ssl = false
    @protocol = nil
    @remote_addr = nil
    @remote_host = nil
    @server_name = nil
    @server_port = nil # Net::HTTP.default_port
  end

  METHOD = nil
  REQUEST_HAS_BODY = nil
  RESPONSE_HAS_BODY = nil

  # Reads a AJP packet from +io+, creates the new AJP13Request object
  # corresponding to the packet, and returns the object.
  #
  # When the request has the entity body, also reads some packets from +io+
  # until the body ends. You can get the entity body as +request+.+body+.
  #
  # +io+:: packet source
  #        [pre-condition]
  #           The read position of +io+ is the top of an AJP packet.
  #        [post-condition]
  #           The read position of +io+ is just behind of the AJP packets
  #           corresponding to the returned AJP13Request object.
  #           If an exception raised, the read position is unknown.
  #
  # If called with a block, yields the given block with a fragment of the body
  # on reading the body. 
  #
  def self.from_io(io)
    from_packet(Net::AJP13::Packet.from_io(io))
  end

  def self.from_packet(packet) #:nodoc: internal use
    raise 'The AJP packet is not to application server' unless packet.to_app?
    raise 'The AJP packet is not a forward request' unless
      packet.message_type == FORWARD_REQUEST

    method = packet.read_byte
    method = 
      REQUEST_METHOD_CODES.index(method) ||
      raise("Unrecognized HTTP method code #{method}")

    protocol = packet.read_string
    path = packet.read_string
    
    req = self.new(path)
    req.method = method.to_s.upcase
    req.protocol = protocol

    req.remote_addr = packet.read_string
    req.remote_host = packet.read_string
    req.server_name = packet.read_string
    req.server_port = packet.read_integer
    req.is_ssl = packet.read_boolean

    num_headers = packet.read_integer
    1.upto(num_headers) do
      if packet.peek_byte == 0xA0
        header_name = packet.read_integer
        header_name = 
          SC_REQ_HEADER_NAMES.index(header_name) ||
          raise("Unrecognized HTTP header code #{header_name}")
        header_name = header_name.tr('_', '-')
      else
        header_name = packet.read_string
      end
      req[header_name] = packet.read_string
    end
    loop do
      case attr_name = packet.read_byte
      when nil
        raise 'Missing AJP request packet terminator'
      when REQUEST_TERMINATOR
        break
      when SC_A_REQ_ATTRIBUTE
        attr_name = packet.read_string
      else
        attr_name = SC_A_NAMES.index(attr_name) ||
          raise("Unrecognized AJP request attribute #{attr_name}")
        attr_name = attr_name.to_s
      end
      attr_value = packet.read_string
      req.add_attribute(attr_name, attr_value)
    end

    return req
  end

  def inspect #:nodoc:
    "\#<#{self.class} #{@method}>"
  end

  # Path to request
  attr_reader :path
  alias :request_uri :path

  # HTTP request method
  attr_reader :method
  attr_writer :method #:nodoc: internal use

  # IP address of the HTTP client
  attr_accessor :remote_addr
  # Host name of the HTTP client
  attr_accessor :remote_host
  # HTTP server name
  attr_accessor :server_name
  # HTTP port
  attr_accessor :server_port

  # Returns if it is permitted that the client sends this request
  # with a request body.
  def request_body_permitted?
    @request_has_body
  end

  # Returns if it is permitted that the server sends the corresponding response
  # with a response body
  def response_body_permitted?
    @response_has_body
  end

  # HTTP-side connection is over SSL or not.
  attr_accessor :is_ssl
  alias :is_ssl? :is_ssl
  def is_ssl=(value) #:nodoc:
    @is_ssl = !!value
  end 

  # HTTP protocol name/version
  attr_accessor :protocol

  # Adds request attribute instead of replace
  # Second argument +value+ must be a String
  # 
  # See also #set_attribute
  def add_attribute(name, value)
    name = name.downcase
    @attributes[name] ||= []
    @attributes[name] << value
  end

  # Set the request attribute corresponding to the case-insensitive name.
  # See also #add_attribute
  def set_attribute(name, value)
    @attributes[name.downcase] = [value]
  end

  # Returns an array of attribute values corresponding to the case-insensitive
  # +name+.
  def get_attributes(name)
    name = name.downcase
    values = @attributes[name]
    values and values.dup
  end

  # Deletes request attributes whose name are +name+
  def delete_attribute(name)
    @attributes.delete(name.downcase)
  end

  # Iterates for each request attribute values.
  # +name+ can appears more than once if multiple values exist for the +name+.
  def each_attribute(&block) #:yield: +name+, +value+
    @attributes.each do |name, values|
      values.each do |value|
        yield name, value
      end
    end
  end

  # Request body part
  attr_accessor :body
  # Stream like a IO object that provides the request body part
  attr_accessor :body_stream
  
  def send_to(io)
    to_packet.send_to(io)
  end

  # Returns an AJP packet object that represents the FORWARD_REQUEST packet
  # corresponding to this request.
  def to_packet
    packet = Net::AJP13::Packet.new
    packet.direction = :to_app
    packet.append_byte FORWARD_REQUEST
    packet.append_byte REQUEST_METHOD_CODES[method.upcase.intern]

    # Mandatory parameters
    [:protocol, :request_uri].each do |name|
      raise "Mandatory parameter #{name} not supplied." unless __send__(name)
      packet.append_string self.__send__(name)
    end
    [:remote_addr, :remote_host, :server_name].each do |name|
      packet.append_string self.__send__(name)
    end
    raise "Mandatory parameter server_port not supplied" unless server_port
    packet.append_integer server_port

    packet.append_boolean is_ssl?
    
    packet.append_integer self.length
    self.each_header do |key, val|
      if packed_name = SC_REQ_HEADER_NAMES[key.downcase]
        packet.append_integer packed_name
        packet.append_string val
      else
        packet.append_string key
        packet.append_string val
      end
    end
    self.each_attribute do |key, val|
      if packed_name = SC_A_NAMES[key.downcase.to_sym]
        packet.append_byte packed_name
        packet.append_string val
      else
        packet.append_byte SC_A_REQ_ATTRIBUTE
        packet.append_string key
        packet.append_string val
      end
    end
    packet.append_byte REQUEST_TERMINATOR

    return packet
  end
end

[
  [ 'OPTIONS',         true,  true,  'Options'        ],
  [ 'GET',             false, true,  'Get'            ],
  [ 'HEAD',            false, false, 'Head'           ],
  [ 'POST',            true,  true,  'Post'           ],
  [ 'PUT',             true,  true,  'Put'            ],
  [ 'DELETE',          false, true,  'Delete'         ],
  [ 'TRACE',           true,  true,  'Trace'          ],
  [ 'PROPFIIND',       true,  true,  'PropFind'       ],
  [ 'PROPPATCH',       true,  true,  'PropPatch'      ],
  [ 'MKCOL',           true,  true,  'MkCol'          ],
  [ 'COPY',            true,  true,  'Copy'           ],
  [ 'MOVE',            true,  true,  'Move'           ],
  [ 'LOCK',            true,  true,  'Lock'           ],
  [ 'UNLOCK',          false, false, 'Unlock'         ],
  [ 'ACL',             true,  true,  'Acl'            ],
  [ 'REPORT',          true,  true,  'Report'         ],
  [ 'VERSION-CONTROL', true,  true,  'VersionControl' ],
  [ 'CHECKIN',         true,  true,  'CheckIn'        ],
  [ 'CHECKOUT',        true,  true,  'CheckOut'       ],
  [ 'UNCHECKOUT',      true,  true,  'UnCheckOut'     ],
  [ 'SEARCH',          true,  true,  'Search'         ],
  [ 'MKWORKSPACE',     true,  true,  'MkWorkSpace'    ],
  [ 'UPDATE',          true,  true,  'Update'         ],
  [ 'LABEL',           true,  true,  'Label'          ],
  [ 'MERGE',           true,  true,  'Merge'          ],
  [ 'BASELINE_CONTROL',true,  true,  'BaseLineControl'],
  [ 'MKACTIVITY',      true,  true,  'MkActivity'     ]
].each do |method_name, has_req_body, has_res_body, class_name, klass|
  klass = Class.new(Net::AJP13::Request) do
    const_set :METHOD, method_name
    const_set :REQUEST_HAS_BODY, has_req_body
    const_set :RESPONSE_HAS_BODY, has_res_body
  end
  Net::AJP13.const_set "#{class_name}Request", klass
end

# Represents AJP1.3 response
class Net::AJP13::Response
  include Net::HTTPHeader
  include Net::AJP13::Constants

  # :stopdoc:
  REASON_PHRASES = {
    100 => 'Continue',
    101 => 'Switching Protocols',
    200 => 'OK',
    201 => 'Created',
    202 => 'Accepted',
    203 => 'Non-Authoritative Information',
    204 => 'No Content',
    205 => 'Reset Content',
    206 => 'Partial Content',
    300 => 'Multiple Choices',
    301 => 'Moved Permanently',
    302 => 'Moved Temporarily',
    303 => 'See Other',
    304 => 'Not Modified',
    305 => 'Use Proxy',
    400 => 'Bad Request',
    401 => 'Unauthorized',
    402 => 'Payment Required',
    403 => 'Forbidden',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    406 => 'Not Acceptable',
    407 => 'Proxy Authentication Required',
    408 => 'Request Time-out',
    409 => 'Conflict',
    410 => 'Gone',
    411 => 'Length Required',
    412 => 'Precondition Failed',
    413 => 'Request Entity Too Large',
    414 => 'Request-URI Too Large',
    415 => 'Unsupported Media Type',
    500 => 'Internal Server Error',
    501 => 'Not Implemented',
    502 => 'Bad Gateway',
    503 => 'Service Unavailable',
    504 => 'Gateway Time-out',
  }.freeze
  REASON_PHRASES.each do |k,v|; v.freeze end

  # Maps HTTP response header names into their codes
  SC_RES_HEADER_NAMES = {
    0xA001 => 'Content-Type',
    0xA002 => 'Content-Language',
    0xA003 => 'Content-Length',
    0xA004 => 'Date',
    0xA005 => 'Last-Modified',
    0xA006 => 'Location',
    0xA007 => 'Set-Cookie',
    0xA008 => 'Set-Cookie2',
    0xA009 => 'Servlet-Engine',
    0xA00A => 'Status',
    0xA00B => 'WWW-AUthenticate'
  }.freeze
  SC_RES_HEADER_NAMES.each do |k,v|; v.freeze end

  # Maps HTTP response header codes into their names.
  SC_RES_HEADER_CODES = SC_RES_HEADER_NAMES.inject({}) do |memo, item|
    code, name = item
    memo[name.downcase.freeze] = code
    memo
  end
  # :startdoc:

  #
  # Creates a new AJP13Response object
  # +status+:: HTTP response status code. (in integer)
  # +options+:: Hash that contains response headers.
  #             If key is :reason_phrase, it overrides the reason phrase.
  def initialize(status, options = {})
    @status = status.to_i
    @reason_phrase = 
      options[:reason_phrase] || options['reason_phrase'] ||
      REASON_PHRASES[@status]
    initialize_http_header options.reject{|k, v| k.to_sym == :reason_phrase }
  end

  # Status Code
  attr_reader :status
  # Status Code as String
  attr_reader :code
  def code #:nodoc:
    status.to_s
  end

  # Reason Phrase
  attr_reader :reason_phrase
  alias :message :reason_phrase

  # The response body
  attr_accessor :body
  # Input stream like an IO object, which provides the response body.
  attr_accessor :body_stream

  # Creates a new AJP13::Response object based on bytes read from +io+.
  # [Pre-Condition]  The read position of +io+ is the head of an AJP packet
  #                  whose prefix code is SEND_HEADERS.
  # [Post-Condition] The read positioin of +io+ is just behind of the AJP
  #                  packet if no exception raised.
  #                  The read position is unspecified if an exception raised.
  # Raises
  #   AJPPacketError:: if the given packet is bloken.
  #   ArgumentError::  if the given packet is not a SEND_HEADERS packet.
  def self.from_io(io)
    from_packet(Net::AJP13::Packet.from_io(io))
  end

  def self.from_packet(packet) #:nodoc: internal use
    raise ArgumentError, 'The AJP response packet is not from an application container' unless packet.from_app?

    raise ArgumentError, "The AJP response packet is not SEND_HEADERS but #{packet.messge_type}" unless packet.message_type == SEND_HEADERS
    
    status = packet.read_integer
    phrase = packet.read_string
    res = self.new(status, :reason_phrase => phrase)
    
    num_headers = packet.read_integer
    1.upto(num_headers) do
      if packet.peek_byte == 0xA0
        header_code = packet.read_integer
        header_name = SC_RES_HEADER_NAMES[header_code]
	raise Net::AJP13::AJPPacketError, "Unrecognized header code #{header_code}" unless header_name
      else
        header_name = packet.read_string
      end
      header_value = packet.read_string
      res.add_field(header_name, header_value)
    end

    return res
  end

  def send_to(io)
    to_packet.send_to(io)
  end

  # Returns a Net::AJP13::Packet object that represents the SEND_HEADER packet
  # corresponding to this response.
  def to_packet
    packet = Net::AJP13::Packet.new
    packet.direction = :from_app
    packet.append_byte SEND_HEADERS
    packet.append_integer self.status
    packet.append_string self.reason_phrase
    packet.append_integer self.length
    self.each_header do |key, val|
      if packed_name = SC_RES_HEADER_CODES[key.downcase]
        packet.append_integer packed_name
      else
        packet.append_string key
      end
      packet.append_string val
    end
    packet
  end
end

# Raised when ajp session takes an illegal state.
class Net::AJP13::AJPStateError < IOError
end

# Represents errors on AJP packet format
class Net::AJP13::AJPPacketError < IOError
end

# :stopdoc:
# Represents AJP1.3 Packet
class Net::AJP13::Packet
  include Net::AJP13::Constants

  # The magic number that represents a packet is from a web server to
  # an app server.
  AJP13_WS_HEADER = "\x12\x34"
  
  # The magic number that represents a packet is from an app server to
  # a web server.
  # corresponds to 'AB' in ASCII.
  AJP13_SW_HEADER = "\x41\x42"

  # :stopdoc:
  # suiting Ruby 1.9 feature
  if RUBY_VERSION < '1.9'
    # calls private methods
    alias_method :fcall, :__send__
  end
  # :startdoc:
  
  # Creates a new packet object.
  def initialize
    @direction = nil
    @packet_length = 0
    @buf = ''
  end
 
  # Reads an AJP packet from +io+, and creates a Packet object based on it.
  # [Pre-condition] The read position of +io+ is the head of an AJP packet.
  # [Post-condition] The read position of +io+ is just behind of the AJP packet
  #                  header when the object creation succeeded. 
  #                  The read position is unspecified if an exception raised.
  #
  # Raises
  # [AJPPacketError] when the read packet has invalid format.
  # [IOError] when +io+ raises it.
  def self.from_io(io)
    p = self.new
    p.fcall(:initialize_by_io, io)
    p
  end

  # Initializer used by Packet.from_io
  def initialize_by_io(io) #:nodoc: internal use
    header = io.read(4)
    raise Net::AJP13::AJPPacketError, "The AJP packet is broken" unless 
      header and header.length == 4

    case header[0..1]
    when AJP13_WS_HEADER
      @direction = :to_app
    when AJP13_SW_HEADER
      @direction = :from_app
    else
      raise Net::AJP13::AJPPacketError, "Unrecognized AJP packet direction"
    end

    @packet_length = header[2..3].unpack('n')[0]

    @byte_stream = io
    @pos = 0 # read position

    @buf = nil
  end
  private :initialize_by_io
  
  # The value is
  #   [:from_app] if this packet is from an app server to a web server.
  #   [:to_app] if this packet is from an web server to an app server.
  #   [nil] if this packet's direction has not been not specified yet.
  attr_accessor :direction

  def direction=(val) #:nodoc:
    if [nil, :to_app, :from_app].include? val
      @direction = val
    else
      raise ArgumentError, "Illegal packet direction value #{val}"
    end
  end

  # returns whether the packet is from a web server to an app server
  def to_app?
    direction == :to_app
  end

  # return wheter the packet is from an app server to a web server
  def from_app?
    direction == :from_app
  end

  def append_bytes(bytes)
    @buf << bytes
  end

  def append_byte(val)
    raise ArgumentError, "Too large to pack into a byte: #{val}" if val > 0xFF
    @buf << [val].pack('C')
  end

  def append_boolean(val)
    @buf <<
      if val then "\x01" else "\x00" end
  end
  def append_integer(val)
    val = val.to_int
    raise ArgumentError, "#{val} is too large to store into an AJP packet" if
      val > 0xFFFF
    @buf << [val].pack('n')
  end
  def append_string(str)
    if str.nil?
      @buf << "\xFF\xFF"
    else
      str = str.to_str
      @buf << [str.length].pack('n') << str << "\0"
    end
  end

  # returns whether the read position is over the packet length.
  def eof?
    @byte_stream.eof? or
      @pos >= @packet_length 
  end

  # Type of message contained in the packet.
  #
  # Reads a byte (type code) from the packet when called first.
  def message_type
    @message_type ||= read_byte
  end

  # Reads bytes from the packet, and advance the read position.
  # returns +nil+ if the read position is over the packet length.
  def read_bytes(length)
    return nil unless @pos < @packet_length
    length = @packet_length - @pos if @packet_length - @pos < length
    bytes = @byte_stream.read(length)
    @pos += bytes.length if bytes
    bytes
  end

  # reads a byte from the packet, and advance the read position.
  # returns +nil+ if the read position is over the packet length.
  def read_byte
    return nil unless @pos < @packet_length
    byte = @byte_stream.getc
    @pos += 1 if byte
    byte
  end

  def unread_byte(byte)
    @byte_stream.ungetc(byte)
    @pos -= 1
    nil
  end

  # reads a byte from the packet, but does not advance the read position.
  # returns +nil+ if the read position is over the packet length.
  def peek_byte
    return nil unless @pos < @packet_length
    byte = @byte_stream.getc
    @byte_stream.ungetc(byte) if byte
    byte
  end

  # reads a boolean value from the packet, and advance the read position.
  # returns +nil+ if the read position is over the packet length.
  def read_boolean
    byte = read_byte

    case byte
    when nil:  nil
    when 0x00: false
    when 0x01: true
    else 
      raise Net::AJP13::AJPPacketError,
        "Can't recognize #{byte} as an boolean value"
    end
  end
  
  # reads a 16bit integer from the packet, and advance the read position.
  # returns +nil+ if the read position is over the packet length.
  def read_integer
    return nil unless @pos < @packet_length
    raise Net::AJP13::AJPPacketError, "too short to read as integer" if
      @packet_length - @pos < 2

    int = @byte_stream.read(2)
    raise Net::AJP13::AJPPacketError, "broken packet" if int.nil?
    @pos += int.length
    raise Net::AJP13::AJPPacketError, "broken packet" if int.length < 2
    int.unpack('n')[0]
  end

  # reads a string from the packet, and advance the read position.
  # returns +nil+ if the read position is over the packet length.
  def read_string
    len = read_integer
    return nil unless len and len != 0xFFFF
    raise Net::AJP13::AJPPacketError, "str length too large: #{len}" if
      len > @packet_length - @pos

    str = @byte_stream.read(len)
    @pos += str.length
    if str.nil? or str.length != len
      raise Net::AJP13::AJPPacketError, "Invalid string format"
    end

    trailer = @byte_stream.getc
    @pos += 1 if trailer
    raise Net::AJP13::AJPPacketError, "Missing trailing NUL" unless trailer == 0x00

    str
  end

  # Sends this packet into the specified socket
  # +io+:: IO object to which this packet will be written.
  def send_to(io)
    raise 'The packet is too large' if @buf.length > 0xFFFF + 4
    warn "The packet is too larget for some implementations: #{@buf.length} bytes" if @buf.length > MAX_PACKET_SIZE

    header = "\0\0\0\0"
    header[0..1] = 
      case @direction
      when :from_app
        AJP13_SW_HEADER
      when :to_app
        AJP13_WS_HEADER
      else
        raise Net::AJP13::AJPPacketError, 'Packet direction not specified'
      end

    header[2..3] = [@buf.length].pack('n')
    io.write header
    io.write @buf
    io.flush
  end

  # length of the packet content, without including the payload
  def length
    if @buf
      @buf.length
    else
      @packet_length
    end
  end
end
# :startdoc:

