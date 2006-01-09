require 'test/unit'
require 'stringio'
require File.dirname(__FILE__) + '/../../lib/net/ajp13server'

class Net::AJP13::Server
  unless method_defined?(:fcall)
    alias :fcall :__send__
  end
end

class Net::AJP13::Server::BodyInputTest < Test::Unit::TestCase
  CONTENTS = [
    # line <-> chunk packet
    "\xf8\xef\x2e\x7e\x1e\x76\x2d\x63\x67\x6c",
    "\xea\xa3\x6c\xfd\x32\x6e\x22\x49\xc6\x58",
    "\x13\x23\x45\x72\xc2\x5b\x08\x2d\xd0\x90",
    "\x91\x8e\xcc\x80\x66\x74\x6d\x61\xd8\x54",
    "\xea\x6e\x27\xc4\x37\xc1\x15\xb5\x64\x73",
    "\x2f\x77\x02\x77\x47\xab\x79\x9b\x91\xc8",
    "\x97\x39\x12\xbb\xbf\x7b\x1c\xe3\x74\xd0",
    "\x91\x7d\x47\x78\x9e\xc4\xfa\xd6\x05\x60",
    "\xbb\x31\xe7\xb5\x0f\xb0\xb8\xd1\xaf\xe3",
    "\x63\xb0\x27\x3e\x08\x45\x5e\x57\xbf\xab",
  ].freeze  # 100 bytes

  class MockSocket
    def initialize(contents)
      @bodies = (
        contents.map{|c| "\x12\x34#{[c.length].pack('n')}" + c } << 
	"\x12\x34\x00\x00"
      ).map {|str| StringIO.new(str)}
      @write_buf = ''
      @written_packets = []
    end
    attr_reader :written_packets

    def read(length)
      io = @bodies[@io_index ||= 0]
      str = io.read(length)
      raise 'packet over run' if str.length != length
      @io_index += 1 if io.eof?
      str
    end
    alias :readpartial :read

    def write(str)
      @write_buf << str
    end

    def eof?
      @io_index >= @bodies.length
    end
    def flush
      @written_packets << @write_buf
      @write_buf = ''
    end
    attr_accessor :sync
    def ungetc(char)
      if eof?
        @io_index = @bodies.length - 1
      elsif @bodies[@io_index].pos == 0
	raise IOError, "can't ungetc" if @io_index == 0
        @io_index -= 1
      end
      @bodies[@io_index].ungetc(char)
    end
  end

  def setup
    @mock_sock = MockSocket.new(CONTENTS)
    @body_input = Net::AJP13::Server::BodyInput.new(@mock_sock, 100)
  end

  def test_length
    assert_equal 100, @body_input.length
    assert_equal 100, @body_input.size
  end

  def test_binmode
    assert_same @body_input, @body_input.binmode
  end
  def test_clone
    assert_raise(TypeError) { @body_input.clone }
  end
  def test_dup
    assert_raise(TypeError) { @body_input.dup }
  end

  def test_close
    @body_input.close
    assert_raise(IOError) { @body_input.read(1) }
  end

  def test_freeze
    assert !@body_input.frozen?
    @body_input.freeze
    assert @body_input.frozen?
    assert_raise(TypeError) { @body_input.read(1) }
  end

  def test_close_read
    @body_input.close_read
    assert_raise(IOError) { @body_input.read(1) }
  end

  def test_closed?
    assert !@body_input.closed?
    @body_input.close
    assert @body_input.closed?
  end

  def test_each_byte
    i = 0
    @body_input.each_byte do |byte|
      assert_equal CONTENTS[i/10][i%10], byte
      i += 1
    end
  end

  def test_eof?
    assert !@body_input.eof?
    @body_input.read(100)
    assert @body_input.eof?
  end
  def test_eof
    assert !@body_input.eof
    @body_input.read(37)
    @body_input.read(63)
    assert @body_input.eof
  end

  def test_fcntl
    require 'fcntl'
    assert_raise(NotImplementedError){@body_input.fcntl(Fcntl::F_DUPFD)}
  end

  def test_fileno
    assert_nil @body_input.fileno
    assert_nil @body_input.to_i
  end

  def test_getc
    assert_equal [], @mock_sock.written_packets
    assert_equal CONTENTS[0][0], @body_input.getc
    assert_equal CONTENTS[0][1], @body_input.getc
    assert_equal CONTENTS[0][2], @body_input.getc
    assert_equal CONTENTS[0][3], @body_input.getc
    assert_equal CONTENTS[0][4], @body_input.getc
    assert_equal CONTENTS[0][5], @body_input.getc
    assert_equal CONTENTS[0][6], @body_input.getc
    assert_equal CONTENTS[0][7], @body_input.getc
    assert_equal CONTENTS[0][8], @body_input.getc
    assert_equal CONTENTS[0][9], @body_input.getc
    assert_equal [], @mock_sock.written_packets

    assert_equal CONTENTS[1][0], @body_input.getc
    assert_equal ["\x41\x42\x00\x03\x06\x00\x5A"], @mock_sock.written_packets

    88.times do @body_input.getc end

    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14",
      "\x41\x42\x00\x03\x06\x00\x0A"
    ], @mock_sock.written_packets

    assert_equal CONTENTS[9][9], @body_input.getc
    assert_nil @body_input.getc
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14",
      "\x41\x42\x00\x03\x06\x00\x0A"
    ], @mock_sock.written_packets
  end

  def test_read_all
    assert !@body_input.eof?
    assert_equal [], @mock_sock.written_packets
    assert_equal CONTENTS.join, @body_input.read
    assert @body_input.eof?
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14",
      "\x41\x42\x00\x03\x06\x00\x0A"
    ], @mock_sock.written_packets

    assert_equal '', @body_input.read
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14",
      "\x41\x42\x00\x03\x06\x00\x0A"
    ], @mock_sock.written_packets
  end

  def test_read_with_length
    assert_equal [], @mock_sock.written_packets
    assert !@body_input.eof?
    # 0...1.
    assert_equal CONTENTS[0][0,1], @body_input.read(1)
    assert_equal [], @mock_sock.written_packets
    assert !@body_input.eof?
    # 1...9
    assert_equal CONTENTS[0][1,8], @body_input.read(8)
    assert_equal [], @mock_sock.written_packets
    assert !@body_input.eof?
    # 9...53
    assert_equal CONTENTS[0][9,1] + CONTENTS[1...5].join + CONTENTS[5][0,3],
      @body_input.read(44)
    assert !@body_input.eof?
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32"
    ], @mock_sock.written_packets
    # 53...60
    assert_equal CONTENTS[5][3,7], @body_input.read(7)
    assert !@body_input.eof?
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32"
    ], @mock_sock.written_packets
    # 60...70
    assert_equal CONTENTS[6], @body_input.read(10)
    assert !@body_input.eof?
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28"
    ], @mock_sock.written_packets
    # 70...81
    assert_equal CONTENTS[7] + CONTENTS[8][0,1], @body_input.read(11)
    assert !@body_input.eof?
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14"
    ], @mock_sock.written_packets
    # 81...91
    assert_equal CONTENTS[8][1,9] + CONTENTS[9][0,1], @body_input.read(10)
    assert !@body_input.eof?
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14",
      "\x41\x42\x00\x03\x06\x00\x0A"
    ], @mock_sock.written_packets
    # 91...110(100)
    assert_equal CONTENTS[9][1,9], @body_input.read(19)
    assert @body_input.eof?
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14",
      "\x41\x42\x00\x03\x06\x00\x0A"
    ], @mock_sock.written_packets

    assert_nil @body_input.read(100000)
    assert_equal "", @body_input.read
    assert_equal [
      "\x41\x42\x00\x03\x06\x00\x5A",
      "\x41\x42\x00\x03\x06\x00\x50",
      "\x41\x42\x00\x03\x06\x00\x46",
      "\x41\x42\x00\x03\x06\x00\x3C",
      "\x41\x42\x00\x03\x06\x00\x32",
      "\x41\x42\x00\x03\x06\x00\x28",
      "\x41\x42\x00\x03\x06\x00\x1E",
      "\x41\x42\x00\x03\x06\x00\x14",
      "\x41\x42\x00\x03\x06\x00\x0A"
    ], @mock_sock.written_packets
  end

  def test_read_with_length_and_buffer
    assert !@body_input.eof?

    buf = '\0' * 23
    # 0...23
    actual = @body_input.read(23, buf)
    assert !@body_input.eof?
    assert_same buf, actual
    assert_equal CONTENTS[0] + CONTENTS[1] + CONTENTS[2][0,3], actual
    # 23...46
    actual = @body_input.read(23, buf)
    assert !@body_input.eof?
    assert_same buf, actual
    assert_equal CONTENTS[2][3,7] + CONTENTS[3] + CONTENTS[4][0,6], actual
    # 46...69
    actual = @body_input.read(23, buf)
    assert !@body_input.eof?
    assert_same buf, actual
    assert_equal CONTENTS[4][6,4] + CONTENTS[5] + CONTENTS[6][0,9], actual
    # 69...92
    actual = @body_input.read(23, buf)
    assert !@body_input.eof?
    assert_same buf, actual
    assert_equal CONTENTS[6][9,1] + CONTENTS[7] +
                 CONTENTS[8] + CONTENTS[9][0,2], actual
    # 92...115(100)
    actual = @body_input.read(23, buf)
    assert @body_input.eof?
    assert_same buf, actual
    assert_equal CONTENTS[9][2,8], actual
    # 115...138 (out of range)
    actual = @body_input.read(23,buf)
    assert_nil actual
    assert_equal "", buf
    assert @body_input.eof?

    assert_equal "", @body_input.read
  end

  def test_readchar
    assert !@body_input.eof?
    assert_equal CONTENTS[0][0], @body_input.readchar
    assert_equal CONTENTS[0][1], @body_input.readchar
    assert_equal CONTENTS[0][2], @body_input.readchar
    assert_equal CONTENTS[0][3], @body_input.readchar
    assert_equal CONTENTS[0][4], @body_input.readchar
    assert_equal CONTENTS[0][5], @body_input.readchar
    assert_equal CONTENTS[0][6], @body_input.readchar
    assert_equal CONTENTS[0][7], @body_input.readchar
    assert_equal CONTENTS[0][8], @body_input.readchar
    assert_equal CONTENTS[0][9], @body_input.readchar

    assert_equal CONTENTS[1][0], @body_input.readchar
    88.times do @body_input.readchar end
    assert_equal CONTENTS[9][9], @body_input.readchar
    assert_raise(EOFError) { @body_input.readchar }
    assert @body_input.eof?
  end

  def test_readline
    mock_sock = MockSocket.new([
      "123456789ABC\n571",
      "string\nfragment\n",
      "This is a long l",
      "ine.\nThis is a m",
      "ore more long li",
      "ne.\nAnd this is ",
      "the last line :P"
    ])
    body_input = Net::AJP13::Server::BodyInput.new(mock_sock, 0x70)
    assert_nil body_input.lineno
    assert_equal "123456789ABC\n", body_input.readline
    assert_equal 1, body_input.lineno
    assert_equal "571string\n", body_input.readline
    assert_equal 2, body_input.lineno
    assert_equal "fragment\n", body_input.readline
    assert_equal 3, body_input.lineno
    assert_equal "This is a long line.\n", body_input.readline
    assert_equal 4, body_input.lineno
    assert_equal "This is a more more long line.\n", body_input.readline
    assert_equal 5, body_input.lineno
    assert_equal "And this is the last line :P", body_input.readline
    assert_equal 6, body_input.lineno
  end

  def test_each_line
    mock_sock = MockSocket.new([
      "123456789ABC\n571",
      "string\nfragment\n",
      "This is a long l",
      "ine.\nThis is a m",
      "ore more long li",
      "ne.\nAnd this is ",
      "the last line :P"
    ])
    body_input = Net::AJP13::Server::BodyInput.new(mock_sock, 0x70)
    expected = [
      "123456789ABC\n", "571string\n", "fragment\n", 
      "This is a long line.\n", "This is a more more long line.\n",
      "And this is the last line :P"
    ]

    i = 0
    body_input.each_line do |line|
      assert_equal expected[i], line
      assert_equal i+1, body_input.lineno
      i += 1
    end
  end

  def test_sync
    @mock_sock.sync = expected = Object.new
    assert_equal expected, @body_input.sync

    expected = Object.new
    assert_equal expected, (@body_input.sync = expected)
    assert_equal expected, @mock_sock.sync
  end

  def test_ungetc
    c = @body_input.getc
    assert_nil @body_input.ungetc(c)
    assert_equal c, @body_input.getc

    assert_equal CONTENTS[0][1,9], @body_input.read(9)
    assert_nil @body_input.ungetc(c)
    assert_equal c, @body_input.getc

    assert_equal CONTENTS[1,9].join, @body_input.read(90)
    assert_nil @body_input.ungetc(c)
    assert_equal c, @body_input.getc
    assert_nil @body_input.getc
  end
end


class Net::AJP13::ServerTest < Test::Unit::TestCase
  TEST_PORT = 3009 
  def setup
    @serv = Net::AJP13::Server.new('localhost', TEST_PORT)
  end

  def test_new
    assert_equal 'localhost', @serv.host
    assert_equal TEST_PORT, @serv.service

    serv = Net::AJP13::Server.new(TEST_PORT)
    assert_nil serv.host
    assert_equal TEST_PORT, serv.service

    serv = Net::AJP13::Server.new
    assert_nil serv.host
    assert_equal Net::AJP13::Constants::DEFAULT_PORT, serv.service

    assert_raise(ArgumentError, 'wrong number of arguments (3 for 0..2)') {
      serv = Net::AJP13::Server.new 'localhost', 3009, 'extra arg'
    }
  end

  def test_process_ping
    ping = "\x12\x34\x00\x01\x0A" # CPING
    io = StringIO.new(ping.dup) 
    @serv.fcall(:process, io)
    io.pos = ping.length
    assert_equal "\x41\x42\x00\x01\x09", io.read
  end

  def test_process_shutdown
    shutdown = "\x12\x34\x00\x01\x07" # SHUTDOWN
    io = StringIO.new(shutdown.dup)
    def io.addr
      ['AF_INET', 3009, 'localhost.localdomain', '127.0.0.1']
    end
    def io.peeraddr
      ['AF_INET', 12345, 'localhost.localdomain', '127.0.0.1']
    end

    @serv.fcall(:process, io)

    io.pos = shutdown.length
    assert_equal "", io.read
  end

  def test_process_request
    req = "" + 
      "\x12\x34\x00\x5c" +          # payload
      "\x02\x03" +                  # FORWARD_REQUEST HEAD
      "\x00\x08HTTP/1.1\x00" +      # protocol = HTTP/1.1
      "\x00\x01/\x00" +             # request_path = /
      "\x00\x09127.0.0.1\x00" +     # remote_addr = 127.0.0.1
      "\x00\x09localhost\x00" +     # remote_host = localhost
      "\x00\x09localhost\x00" +     # server_name = localhost
      "\x00\x50" +                  # server_port = 80
      "\x00" +                      # is_ssl = false
      "\x00\x01" +                  # num_headers = 1
      "\xA0\x0B" +                  #  Host:
      "\x00\x09localhost\0" +       #   localhost
      "\x05" +                      # QUERY_STRING = 
      "\x00\x0Fq=something&a=1\x00"+#  "q=something&a=1"
      "\xFF" +                      # TERMINATOR 
     ""
    io = StringIO.new(req.dup)

    assert_raise(Net::AJP13::Server::ProcessRequestNotImplementedError) {
      @serv.fcall(:process, io)
    }

    io = StringIO.new(req.dup)
    class << @serv
      def process_request(req)
        res = Net::AJP13::Response.new(204)
      end
    end

    @serv.fcall(:process, io)
    io.pos = req.length
    assert_equal "" +
      "\x41\x42\x00\x12" +                  # prefix length
      "\x04" +                              # SEND_HEADERS
      "\x00\xCC\x00\x0ANo Content\x00" +    # 204 No Content
      "\x00\x00" +                          # num_headers = 0
      "" +
      "\x41\x42\x00\x02" +                  # prefix length 
      "\x05" +                              # END_RESPONSE
      "\x01" +                              # reuse = true
      "",
      io.read
  end
end

