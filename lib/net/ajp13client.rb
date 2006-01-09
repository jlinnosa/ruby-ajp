# = Ruby/AJP client
#
# Client-side library for AJP1.3
#
# ==Example
#
# === Simple GET
#    require 'net/ajp13client'
#    Net::AJP13::Client.start('localhost') do |client|
#      puts client.get('/index.jsp').body
#    end
#
# === More about GET
#    require 'net/ajp13client'
#    req = Net::AJP13::GetRequest.new('/index.jsp')
#    req.server_port = 80
#    req['Host'] = 'www.example.com'
#    res = Net::AJP13::Client.start('localhost') do |client|
#      client.request(req) do |frag|
#        $stderr.puts "got a fragment of the content body."
#        puts frag
#      end
#    end
#    $stderr.puts "Response body was #{res.content_length} bytes"
#    $stderr.puts "Headers:"
#    res.each do |name, value|
#      $stderr.puts "#{name}: #{value}"
#    end   
#
# == Copyright
# Author:: Yugui (mailto:yugui@yugui.sakura.ne.jp)
# Copyright:: *
#             * Copyright (c) 2005-2006 Yugui
#             * Copyright (c) 1999-2005 Yukihiro Matsumoto
#             * Copyright (c) 1999-2005 Minero Aoki
#             * Copyright (c) 2001 GOTOU Yuuzou
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
# Net::AJP13::Client was implemented by refering net/http, rev. 1.128.
# Especially, its RDoc documentation is derived from Net::HTTP's one, which was
# written by Minero Aoki and converted to RDoc by William Webber.
#
# The original net/http is available from http://www.ruby-lang.org/cgi-bin/cvsweb.cgi/ruby/lib/net/http.rb?rev=1.128
#

require 'socket'
require 'timeout'
require 'net/ajp13'
require 'stringio'

# :stopdoc:
module Net; end
module Net::AJP13; end
# :startdoc:


#
# AJP1.3 client
#
class Net::AJP13::Client
  include Net::AJP13::Constants

  # Creates a new Net::AJP13::Client object for the specified +address+.
  # +address+:: The FQDN of the servlet container to connect toe.
  # +port+:: The port number to connect to.
  # This method does not open the TCP connection.
  def initialize(address, port = DEFAULT_PORT)
    @address = address
    @port = port || DEFAULT_PORT
    @state = nil

    @open_timeout = 30
    @read_timeout = 60
    @write_timeout = 60
  end

  def inspect #:nodoc:
    "#<#{self.class} #{@address}:#{@port} state=#{@state}>"
  end

  # The host name to connect to.
  attr_reader :address
  # The port number to connect to.
  attr_reader :port

  # State of the TCP/AJP connection. The value is
  # +nil+ ::
  #   If neither TCP connection nor AJP session is opened.
  # :idle ::
  #   If a TCP connection is opened but no request is
  #   being handled over the connection.
  # :assigned ::
  #   If the TCP connection is opened and handling a specific request.
  attr_reader :state

  # returns true if the TCP connection is opened.
  def started?; !!@state end
  # alias of #started?
  alias :active? :started?

  # returns true if the TCP connection is handling a specific request.
  def assigned?; @state == :assigned end

  # returns true if the TCP connection is opened, but no request is being
  # handled over the connection.
  def idle?; @state == :idle end


  # Seconds to wait until connection is opened.
  # If the Client object cannot open a connection in this many seconds,
  # it raises a TimeoutError exception.
  attr_accessor :open_timeout

  # Seconds to wait until reading one block (by one read(2) call).
  # It raises a TimeoutError exception when timeout
  attr_accessor :read_timeout

  # Seconds to wait until writing one block (by one write(2) call).
  # It raises a TimeoutError exception when timeout
  attr_accessor :write_timeout

  # Opens TCP connection and AJP session.
  # Raises IOError if already started.
  # 
  # When this method is called with block, gives a HTTP object to the block
  # and closes the TCP connection after the block executed.
  #
  # When called with a block, returns the return value of the block;
  # otherwise, returns self.
  def start #:yields: self if block given
    raise IOError, 'AJP session already opended' if @state
    Timeout.timeout(@open_timeout) {
      @socket = TCPSocket.new(address, port)
    }
    @state = :idle
    if block_given?
      begin
        return yield(self)
      ensure
        finish if started?
      end
    else
      return self
    end
  end

  # Creates a new Net::AJP13::Client object for the specified +address+,
  # and opens its TCP connection and AJP session. 
  #
  # If the optional block is given, the newly created Net::AJP13::Client object
  # is passed to it and closed when the block finishes.
  # 
  # When called with a block, returns the return value of the block;
  # otherwise, returns the newly created Net::AJP13::Client object.
  #
  # +address+:: The FQDN of the servlet container to connect toe.
  # +port+:: The port number to connect to.
  def self.start(address, port = DEFAULT_PORT, &block) # :yield: +ajp13+
    self.new(address, port).start(&block)
  end

  # Closes TCP connection.
  # Raises AJPStateError if not started.
  def finish
    raise Net::AJP13::AJPStateError, 'AJP session not yet started' unless @state
    @socket.close unless @socket.closed?
    @state = @socket = nil
  end

  # Ensures that +self+ is taking :idle state.
  def ensure_idling
    raise Net::AJP13::AJPStateError,
      'AJP session not yet started' unless started?
    raise Net::AJP13::AJPStateError, 
      "AJP session has already been in `assigned\'" unless idle?
  end
  private :ensure_idling

  # Asks the application server to shut itself down.
  def ask_to_shutdown
    ensure_idling

    packet = Net::AJP13::Packet.new
    packet.direction = :to_app
    packet.append_byte SHUTDOWN

    packet.send_to(@socket)
  end


  # Sends ping message to the application server.
  # Raises
  # [IOError] if the TCP socket raises it.
  # [TimeOutError]
  def ping
    ensure_idling

    packet = Net::AJP13::Packet.new
    packet.direction = :to_app
    packet.append_byte CPING

    packet.send_to(@socket)

    packet = Net::AJP13::Packet.from_io(@socket)
    case packet.message_type
    when CPONG_REPLY
      return true
    when SEND_BODY_CHUNK, SEND_HEADERS, END_RESPONSE, GET_BODY_CHUNK
      raise Net::AJP13::AJPStateError, 
        "Unexpected packet type #{packet.message_type}"
    else
      raise Net::AJP13::AJPPacketError, 
        "Unrecognized packet type #{packet.message_type}"
    end
  end


  # read a bytes from +io+, and returns BODY_CHUNK packet to send the bytes.
  def body_chunk_packet(io, max_len)
    chunk = io.eof? ? '' : io.readpartial(max_len)
    packet = Net::AJP13::Packet.new
    packet.direction = :to_app
    packet.append_integer chunk.length
    packet.append_bytes chunk
    packet
  end


  # Sends +req+ to the connected application server.
  #
  # Returns a Net::AJP13::Reponse object, which represents the received 
  # response.
  # Raises AJPStateError unless the session state is :idle.
  #
  # If called with a block, yields each fragment of the
  # entity body in turn as a string as it is read from
  # the socket.  Note that in this case, the returned response
  # object may not contain a (meaningful) body.
  #
  # If the application server says that the connection is not `reusable',
  # this method calls #finish after receiving the response.
  def request(req) #:yields: +response_body_fragment+
    ensure_idling
    @state = :assigned

    begin
      req.protocol ||= 'HTTP/1.0'
      req['host'] ||= address
      req.server_port ||= 80

      if req.body
        req['content-length'] ||= req.body.length.to_s
	req['content-type'] ||= 'application/x-www-from-urlencoded'
	body_stream = StringIO.new(req.body)
      elsif req.body_stream
        if req['content-length']
	  body_stream = req.body_stream
	else
	  if req.body_stream.respond_to?(:length)
	    req['content-length'] = req.body_stream.length.to_s
	    body_stream = req.body_stream
	  else
	    body_stream = StringIO.new(req.body_stream.read)
	    req['content-length'] = body_stream.length.to_s
	  end
	end
	req['content-type'] ||= 'application/x-www-from-urlencoded'
      end
      
      req.send_to @socket
      packet = nil
      if body_stream
        # Mainly, for StringIO
        unless body_stream.respond_to?(:readpartial)
	  class << body_stream
	    alias_method :readpartial, :read
	  end
	end

        chunk = 
	  body_chunk_packet(body_stream, MAX_BODY_CHUNK_SIZE)
	chunk.send_to @socket

        loop do
          packet = Net::AJP13::Packet.from_io(@socket)
          case packet.message_type
          when GET_BODY_CHUNK
            required = packet.read_integer
	    chunk = body_chunk_packet(body_stream, 
	                              [required, MAX_BODY_CHUNK_SIZE].min)
	    chunk.send_to @socket
            next
          when SEND_HEADERS
            break
          when SEND_BODY_CHUNK, END_RESPONSE
            raise Net::AJP13::AJPStateError, 'Unexpected state'
          else
            raise Net::AJP13::AJPPacketError, 
	      "Unrecognized packet type : #{packet.message_type}"
          end
        end
      else
        packet = Net::AJP13::Packet.from_io(@socket) 
      end

      res = Net::AJP13::Response.from_packet(packet)
      loop do
        packet = Net::AJP13::Packet.from_io(@socket)
        case packet_type = packet.read_byte
        when GET_BODY_CHUNK, SEND_HEADERS
          raise AJPError, 'Unexpected state'
        when SEND_BODY_CHUNK
          len = packet.read_integer
          body = packet.read_bytes(len)
	  terminator = packet.read_byte # TODO: This terminator is undocumented.
          # raise AJPError, 'Block packet' unless packet.eof?
          if block_given?
            yield body
          else
            res.body ||= ''
            res.body << body
          end
          next
        when END_RESPONSE
          is_reusable = packet.read_boolean
          finish unless is_reusable
          break
        else
          raise Net::AJP13::AJPPacketError, 
	    "Unrecoginized packet type #{packet_type}"
        end
      end
    ensure
      @state = :idle
    end

    return res
  end

  # Equals #request(GetRequest.new(+path+, +header+)) in this version.
  def get(path, header = nil, &block)
    request(Net::AJP13::GetRequest.new(path, header), &block)
  end
end


