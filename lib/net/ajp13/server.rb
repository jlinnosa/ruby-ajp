# == Ruby/AJP server
# === Examples
# See example/ directory
#
# === Copyright
# Author:: Yugui (mailto:yugui@yugui.sakura.ne.jp)
# Copyright:: Copyright (c) 2006 Yugui
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

require 'socket'
require 'ipaddr'
require 'mutex_m'
require 'timeout'
require 'stringio'
require 'net/ajp13'

# :stopdoc:
module Net; end
module Net::AJP13; end
# :startdoc:

# Provides a skeleton to implement an AJP 1.3 server.
class Net::AJP13::Server
  include Net::AJP13::Constants
  include Mutex_m

  # 
  # +host+:: Host to bind. If ommited or +nil+, the server will accept requests
  #          from any hosts.
  # +serivce+:: Port number to bind. It can be a service name registered in
  #             /etc/services (or NIS). 
  def initialize(*args) #:args: [host,] service = DEFAULT_PORT
    @host = nil
    @service = DEFAULT_PORT

    case args.length
    when 2
      @host = args[0] if args[0]
      @service = args[1] if args[1]
      @open_socket = lambda{ TCPServer.new(@host, @service) }
    when 1
      @service = args[0] if args[0]
      @open_socket = lambda{ TCPServer.new(@service) }
    when 0
      @open_socket = lambda{ TCPServer.new(@service) }
    else
      raise ArgumentError, "wrong number of arguments (#{args.length} for 0..2)"
    end
  end

  # The instance accepts only requests from #host.
  # If host is +nil+, it accepts requests from any hosts.
  # See Also:: TCPServer.new, bind(2)
  attr_reader :host

  # The port number to bind.
  attr_reader :service

  # logger
  attr_accessor :logger
  def logger #:nodoc:
    unless @logger
      require 'logger'
      @logger = Logger.new(STDOUT)
    end
    @logger
  end


  #
  # Starts the server; opens the socket, begins accepting requests, ....
  # +sock+:: If not nil, the server uses +sock+ instead of opening a new socket.
  def start(sock = nil)
    if sock
      @sock = sock
    else
      @sock = @open_socket.call
    end

    @sock.listen(5)
    begin
      until @shutdown
        accepted = @sock.accept
	Thread.new {
	  begin
	    accepted.sync = false
            process(accepted)
	  rescue StandardError => err
	    logger.error("#{err.message} from #{err.backtrace.join("\n")}")
	  rescue Object => err
	    logger.fatal("#{err.message} from #{err.backtrace.join("\n")}")
	  else
	    logger.debug("closed")
	  ensure
	    accepted.close unless accepted.closed?
	  end
	}
      end
    end

    logger.info("Exited normally.")
  rescue Interrupt
    logger.info("Exited by Interrupt.")
  ensure
    @sock.close if @sock and !@sock.closed?
  end


  # You must override this method. The default implementation simply raises
  # a ProcessRequestNotImplementedError.
  # +request+:: The Net::AJP13::Request object that represents an accepted
  #             AJP request.
  # The return value must be a Net::AJP13::Response object.
  def process_request(request)
    raise ProcessRequestNotImplementedError, "Must be overridden."
  end

  private

  # +conn+:: Accepted connection. +conn+ is an IO object or something like it.
  def process(conn)
    loop do
      break unless c = conn.getc
      conn.ungetc c

      packet = Net::AJP13::Packet.from_io(conn)
      case packet.message_type
      when FORWARD_REQUEST
        process_forward_request(packet, conn)
      when SHUTDOWN
        process_shutdown(packet, conn)
      when PING
        process_ping(packet, conn)
      when CPING
        process_cping(packet, conn)
      else
        raise Net::AJP13::AJPPacketError, "Unrecognized packet type #{packet.message_type}"
      end
    end
  end


  # Handler for FORWARD_REQUEST message.
  #
  # Normally, you should override #process_request instead of overriding this
  # method directly.
  def process_forward_request(packet, conn)
    req = Net::AJP13::Request.from_packet(packet)
    if req['content-length'] and req.content_length > 0
      req.body_stream = BodyInput.new(conn, req.content_length)
    end

    user_code_error = nil
    begin
      res = process_request(req)
    rescue ProcessRequestNotImplementedError
      raise
    rescue Object => err
      user_code_error = err
    end

    if user_code_error
      # sends backtrace
      message = user_code_error.message + ": " +
        user_code_error.backtrace.join("\n")
      logger.error(message)

      message = message[0, MAX_PACKET_SIZE - 4] if
        message.length > MAX_PACKET_SIZE - 4
      res = Net::AJP13::Response.new(500)
      res['content-type'] = 'text/plain'
      res['content-length'] = message.length.to_s
      res.send_to conn
      conn.write "\x41\x42#{[message.length + 4].pack('n')}\x03#{[message.length].pack('n')}#{message}\x00"
    else
      # SEND_HEADERS packet
      res ||= Net::AJP13::Response.new(500)
      res['content-length'] ||= res.body.length.to_s if res.body 
      res.send_to conn

      # SEND_BODY_CHUNK packets
      if res.body
        stream = StringIO.new(res.body)
        until stream.eof?
          chunk = stream.read(MAX_PACKET_SIZE - 4)
          packet = Net::AJP13::Packet.new
          packet.direction = :from_app
	  packet.append_byte SEND_BODY_CHUNK

          # differ from ajpv13a.html, but Tomcat5 acts like this. 
	  packet.append_string chunk

	  packet.send_to conn
        end
      end
    end

    # END_RESPONSE packet
    packet = Net::AJP13::Packet.new
    packet.direction = :from_app
    packet.append_byte END_RESPONSE
    packet.append_boolean !user_code_error
    packet.send_to conn

    conn.close if user_code_error
  end

  # Handler for CPING message
  def process_cping(packet, conn)
    packet = Net::AJP13::Packet.new
    packet.direction = :from_app
    packet.append_byte CPONG_REPLY
    packet.send_to conn
  end

  # Handler for SHUTDOWN message.
  def process_shutdown(packet, conn)
    if IPAddr.new(conn.addr[3]) == IPAddr.new(conn.peeraddr[3])
      shutdown
    end
  end

  # Shuts the server down.
  def shutdown(force = false)
    @shutdown = true
    @sock.close if force
  end

  class ProcessRequestNotImplementedError < NotImplementedError
  end

  # Input stream that corresponds the request body from the web server.
  # BodyInput object acts as an IO except writing methods.
  class BodyInput #:nodoc: all
    include Net::AJP13::Constants
    include Enumerable

    # +sock+:: socket connection to the web server
    # +length+:: Content-Length
    def initialize(sock, length)
      @sock = sock
      @packet = Net::AJP13::Packet.from_io(sock)
      @length = length
      packet_content_length = @packet.read_integer
      @read_length = 0
    end

    # Content-Length
    attr_reader :length
    alias :size :length

    # Does nothing
    def binmode; self end

    # Raises TypeError. You can't clone BodyInput.
    def clone
      raise TypeError, "can't clone #{self.class}"
    end
    alias :dup :clone

    # Closes the BodyInput. 
    # Note that this method does not close the internal socket connection.
    def close
      @packet = @sock = nil
    end

    # Returns true if the BodyInput is closed.
    def closed?
      @sock.nil?
    end
    alias :close_read :close

    # Same as IO#each_byte
    def each_byte
      while ch = getc
        yield ch
      end
    end

    def eof?
      @read_length >= @length 
    end
    alias :eof :eof?

    # Raises NotImplementedError
    def fcntl(*args)
      raise NotImplementedError, "#{self} does not support fcntl"
    end
    # Raises NotImplementedError
    def iocntl(*args)
      raise NotImplementedError, "#{self} does not support iocntl"
    end

    # Always returns nil
    def fileno; nil end
    alias :to_i :fileno

    def getc
      str = read(1)
      str and str[0]
    end
    
    # Returns false
    def isatty; false end
    alias :tty? :isatty

    def lineno; @lineno end

    # Returns nil
    def pid; nil end

    # Returns current read position.
    def pos; @read_length end
    alias :tell :pos

    def read(length = nil, buf = '') #:args: [length[, buf]]
      raise TypeError, "can't modify frozen stream" if frozen?
      raise IOError, 'closed stream' if closed?
      if length.nil?
        return '' if eof?
	length = [0, @length - @read_length].max
      else
        raise ArgumentError, "negative length #{length} given" if length < 0
        if eof?
          buf[0..-1] = ''
	  return nil
	end
      end

      if @packet.eof?
        written_length = 0
      else
        chunk = @packet.read_bytes(length)
        written_length = chunk.length
	@read_length += written_length
        buf[0, written_length] = chunk
      end
      while written_length < length and !eof?
        packet = Net::AJP13::Packet.new
	packet.direction = :from_app
	packet.append_byte GET_BODY_CHUNK
	packet.append_integer [@length - @read_length, MAX_BODY_CHUNK_SIZE].min
	packet.send_to @sock

        @packet = Net::AJP13::Packet.from_io(@sock)
	if @packet.length == 0
	  # this means eof
	  break
	else
          packet_content_length = @packet.read_integer
	  chunk = @packet.read_bytes([length - written_length, packet_content_length].min)
	  buf[written_length, chunk.length] = chunk
	  written_length += chunk.length
	  @read_length += chunk.length
	end
      end
      if written_length < buf.length
        buf[written_length..-1] = ''
      end
      
      return buf
    end


    def readchar
      str = read(1)
      if str.nil?
        raise EOFError
      else
        str[0]
      end
    end

    GETS_BLOCK_SIZE = 256 # :nodoc:
    def gets(rs = $/)
      return read if rs.nil?
      @lineno ||= 0
      @line ||= ''
      pattern = /\A.+?#{rs=='' ? "\\r?\\n\\r?\\n" : Regexp.escape(rs)}/
      until md = pattern.match(@line)
        block = read(GETS_BLOCK_SIZE)
	if block.nil?
	  line = @line
	  @line = nil
	  @lineno += 1
	  return line == '' ? nil : line
	else
          @line << block
	end
      end
      @line = md.post_match
      @lineno += 1
      return md.to_s
    end
    def readline(rs = $/)
      line = gets(rs)
      if line.nil? 
        raise EOFError
      else
        line
      end
    end
    def each_line(rs = $/)
      while line = gets(rs)
        yield line
      end
    end
    alias :each :each_line

    # Raises NotImplementedError
    def reopen(*args)
      raise NotImplementedError, "#{self.class} does not support reopen"
    end

    def sync; @sock.sync end
    def sync=(val); @sock.sync = val end

    alias :sysread :read

    # Returns self
    def to_io; self end

    def ungetc(char)
      raise TypeError, "#{char} is not a Fixnum" unless char.is_a? Fixnum
      raise ArgumentError, "#{char} must be a byte, but negative" if char < 0
      raise ArgumentError, "#{char} is too large to treat as a byte" if char > 0xFF
      @packet.unread_byte(char)
      @read_length -= 1
      nil
    end
  end
end
