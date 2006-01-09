require 'test/unit'
require 'stringio'
require File.dirname(__FILE__) + '/../../lib/net/ajp13'

class Net::AJP13::PacketTest < Test::Unit::TestCase
  def setup
    @packet = Net::AJP13::Packet.new
  end
  def test_direction
    assert_nil @packet.direction

    @packet.direction = :to_app
    assert_equal :to_app, @packet.direction

    @packet.direction = :from_app
    assert_equal :from_app, @packet.direction

    assert_raise(ArgumentError) { @packet.direction = :something_wrong }
    assert_raise(ArgumentError) { @packet.direction = 'to_app' }
  end

  def test_length
    assert_equal 0, @packet.length
  end

  def test_from_io
    data = StringIO.new("\x41\x42\x00\x02\x05\x00") # AJP13_END_RESPONSE packet
    assert_nothing_raised { Net::AJP13::Packet.from_io(data) }
    assert 4, data.pos

    data = StringIO.new("\x12\x34\x00\x01\x0A") # AJP13_CPING
    assert_nothing_raised { Net::AJP13::Packet.from_io(data) }
    assert 4, data.pos

    # packet with unrecognized header
    data = StringIO.new("\x63\x23\x00\x00\x00\x00\x00") 
    assert_raise(Net::AJP13::AJPPacketError) { Net::AJP13::Packet.from_io(data) }
    
    # packet with mismatched length
    data = StringIO.new("\x12\x34\x00\x010\x00\x00\x00")
    # nothing raised until Packet#read_* called
    assert_nothing_raised { Net::AJP13::Packet.from_io(data) }
    assert 4, data.pos

    data = StringIO.new("\x12\x34\x00") # packet with imcomplete length field
    assert_raise(Net::AJP13::AJPPacketError) { Net::AJP13::Packet.from_io(data) }
    assert 4, data.pos
  end

  def test_send_to
    io = StringIO.new
    assert_raise(Net::AJP13::AJPPacketError, 'Packet direction not specified') {
      @packet.send_to(io)
    }

    @packet.direction = :to_app
    @packet.send_to(io)
    io.rewind
    assert_equal "\x12\x34\x00\x00", io.read

    io = StringIO.new
    @packet.direction = :from_app
    @packet.send_to(io)
    io.rewind
    assert_equal "\x41\x42\x00\x00", io.read
  end

  def test_append_byte
    @packet.direction = :from_app
    @packet.append_byte 0x13
    @packet.append_byte 0x35
    assert_raise(ArgumentError) { @packet.append_byte 0x100 }
    assert_raise(ArgumentError) { @packet.append_byte 0x3400 }

    io = StringIO.new
    @packet.send_to(io)
    io.rewind
    assert_equal "\x41\x42\x00\x02\x13\x35", io.read
  end

  def test_append_bytes
    @packet.direction = :from_app
    @packet.append_bytes "abcdefg\x00\x0C\x0A123\x00"
    @packet.append_bytes "\x12\x6A"

    io = StringIO.new
    @packet.send_to(io)
    io.rewind
    assert_equal "\x41\x42\x00\x10abcdefg\x00\x0C\x0A123\x00\x12\x6A", io.read
  end

  def test_append_boolean
    @packet.direction = :from_app
    @packet.append_boolean true
    @packet.append_boolean false
    @packet.append_boolean nil
    @packet.append_boolean 0
    @packet.append_boolean ""
    @packet.append_boolean "0"
    @packet.append_boolean "nil"
    @packet.append_boolean :nil
    @packet.append_boolean "asdf"
    @packet.append_boolean nil

    io = StringIO.new
    @packet.send_to(io)
    io.rewind
    assert_equal "\x41\x42\x00\x0A\x01\x00\x00\x01\x01\x01\x01\x01\x01\x00", 
      io.read
  end

  def test_append_integer
    @packet.direction = :from_app
    @packet.append_integer 0x6789
    @packet.append_integer 0xAB01
    assert_raise(ArgumentError) { @packet.append_integer 0x10000 }
    assert_raise(ArgumentError) { @packet.append_integer 0xFF0000 }
    
    io = StringIO.new
    @packet.send_to(io)
    io.rewind
    assert_equal "\x41\x42\x00\x04\x67\x89\xAB\x01", io.read
  end

  def test_append_string
    @packet.direction = :from_app
    @packet.append_string "test str"
    @packet.append_string "string including NUL(\x00) character"
    @packet.append_string "string ending with NUL\x00"
    @packet.append_string "more string"

    io = StringIO.new
    @packet.send_to(io)
    io.rewind
    assert_equal "" +
      "\x41\x42\x00\x57" +
      "\x00\x08test str\x00" +
      "\x00\x21string including NUL(\x00) character\x00" +
      "\x00\x17string ending with NUL\x00\x00" +
      "\x00\x0Bmore string\x00",
      io.read
  end

  def test_eof
    data = "\x12\x34\x00\x00"
    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert packet.eof?

    data = "\x12\x34\x00\x03\x00\xAF\x00"
    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    packet.read_integer; packet.read_byte
    assert packet.eof?

    data = "\x12\x34\x00\x03\x00\xAF\x00" +
           "extra bytes"
    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    packet.read_integer; packet.read_byte
    assert packet.eof?
  end


  def test_read_byte
    data = "\x12\x34\x00\x08\x12\x34\x56\x78\x9A\xBC\xDE\xF0" +
           "extra bytes"
    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_equal 0x12, packet.read_byte
    assert !packet.eof?
    assert_equal 0x34, packet.read_byte
    assert !packet.eof?
    assert_equal 0x56, packet.read_byte
    assert !packet.eof?
    assert_equal 0x78, packet.read_byte
    assert !packet.eof?
    assert_equal 0x9A, packet.read_byte
    assert !packet.eof?
    assert_equal 0xBC, packet.read_byte
    assert !packet.eof?
    assert_equal 0xDE, packet.read_byte
    assert !packet.eof?
    assert_equal 0xF0, packet.read_byte
    assert packet.eof?
    assert_nil packet.read_byte
    assert_nil packet.read_byte
    assert_nil packet.read_byte
  end

  def test_read_bytes
    data = "\x12\x34\x00\x08\xFE\xDC\xBA\x98\x76\x54\x32\x10"
           "extra bytes"
    data.freeze

    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_equal "\xFE\xDC\xBA\x98\x76\x54\x32\x10", packet.read_bytes(8)
    assert packet.eof?
    assert_nil packet.read_bytes(3)
    assert_nil packet.read_byte
    assert_nil packet.read_bytes(10)

    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_equal "\xFE\xDC\xBA\x98\x76\x54\x32\x10", packet.read_bytes(100)
    assert packet.eof?
    assert_nil packet.read_bytes(3)
    assert_nil packet.read_byte
    assert_nil packet.read_bytes(10)

    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_equal "\xFE\xDC\xBA", packet.read_bytes(3)
    assert !packet.eof?
    assert_equal "\x98\x76\x54", packet.read_bytes(3)
    assert !packet.eof?
    assert_equal "\x32\x10", packet.read_bytes(3)
    assert packet.eof?
    assert_nil packet.read_bytes(3)
    assert_nil packet.read_byte
    assert_nil packet.read_bytes(10)
  end

  def test_read_boolean
    data = "\x41\x42\x00\x05\x01\x01\x00\x01\x03" + "extra bytes"

    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_same true, packet.read_boolean
    assert !packet.eof?
    assert_same true, packet.read_boolean
    assert !packet.eof?
    assert_same false, packet.read_boolean
    assert !packet.eof?
    assert_same true, packet.read_boolean
    assert !packet.eof?
    assert_raise(Net::AJP13::AJPPacketError) { packet.read_boolean }
    assert packet.eof?
    assert_nil packet.read_boolean
    assert_nil packet.read_bytes(10)
    assert_nil packet.read_byte
  end

  def test_read_integer
    data = "\x41\x42\x00\x0B\x00\x01\xCB\x35\x00\x00\x01\x00\xFF\xFF\x00" +
           "extra bytes"
    data.freeze

    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_equal 0x0001, packet.read_integer
    assert !packet.eof?
    assert_equal 0xCB35, packet.read_integer
    assert !packet.eof?
    assert_equal 0x0000, packet.read_integer
    assert !packet.eof?
    assert_equal 0x0100, packet.read_integer
    assert !packet.eof?
    assert_equal 0xFFFF, packet.read_integer
    assert !packet.eof?
    assert_raise(Net::AJP13::AJPPacketError, "too short to read as integer") { 
      packet.read_integer
    }
    assert !packet.eof?
    assert_equal 0x00, packet.read_byte
    assert packet.eof?
    assert_nil packet.read_integer
  end

  def test_read_string
    data = "" + 
      "\x12\x34\x00\x25" +
      "\x00\x0Btest string\x00" +
      "\x00\x0Fstr with NUL(\x00)\x00" +
      "\xFF\xFF" +                         # treated as NULL string
      "\x00\x00\x00" +
      "some extraa bytes"
    data.freeze

    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_equal "test string", packet.read_string
    assert !packet.eof?
    assert_equal "str with NUL(\x00)", packet.read_string
    assert !packet.eof?
    assert_nil packet.read_string
    assert !packet.eof?
    assert_equal "", packet.read_string
    assert packet.eof?
    assert_nil packet.read_string


    data = "" +
      "\x41\x42\x00\x07" +
      "\x00\x03str\x00" +
      "\x00" + # str length incomplete8
      "some extra bytes"
    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_equal "str", packet.read_string
    assert_raise(Net::AJP13::AJPPacketError) { packet.read_string }

    data = "" +
      "\x12\x34\x00\x08" +
      "\x00\x0712345\x00" + # str length too large
      "some extra bytes"
    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_raise(Net::AJP13::AJPPacketError) { packet.read_string }

    data = "" +
      "\x41\x42\x00\x0B" +
      "\x00\x08ABCDabcd" + # missing NUL
      "some extra bytes"
    packet = Net::AJP13::Packet.from_io(StringIO.new(data))
    assert !packet.eof?
    assert_raise(Net::AJP13::AJPPacketError) { packet.read_string }
    assert packet.eof?
  end
end
