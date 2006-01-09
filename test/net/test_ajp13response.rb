require 'test/unit'
require 'stringio'
require File.dirname(__FILE__) + '/../../lib/net/ajp13'

class Net::AJP13::ResponseTest < Test::Unit::TestCase
  def setup
    @res = Net::AJP13::Response.new(301)
  end

  def test_new
    assert_equal 301, @res.status
    assert_equal "301", @res.code
    assert_equal 'Moved Permanently', @res.message
    assert_equal 'Moved Permanently', @res.reason_phrase
    assert_same @res.message, @res.reason_phrase
    assert_nil @res.body
    assert_nil @res.body_stream
  end

  def test_from_io
    packet = 
      "\x41\x42\x00\x2e" +         # "AB" length
      "\x04" +                     # SEND_HEADERS
      "\x00\xC8\x00\x02OK\x00" +   # 200 OK
      "\x00\x02" +                 # num_headers = 2
      "\xA0\x01" +                 # Content-Type:
      "\x00\x18text/html;" +
        " charset=UTF-8\x00" +     #  text/html; charset=UTF-8
      "\xA0\x03" +                 # Content-Length:
      "\x00\x0241\x00" +           #   41
      ""
    io = StringIO.new(packet)
    assert !io.eof?
    res = Net::AJP13::Response.from_io(io)
    assert io.eof?
    assert_equal 200, res.status
    assert_equal '200', res.code
    assert_equal 'OK', res.message
    assert !res.key?('Exprires')
    assert_equal 'text/html; charset=UTF-8', res['content-type']
    assert_equal '41', res['Content-Length']
    assert_nil res.body
    assert_nil res.body_stream

    packet = 
      "\x41\x42\x00\x11" +         # "AB" length
      "\x04" +                     # SEND_HEADERS
      "\x00\xC8\x00\x02OK\x00" +   # 200 OK
      "\x00\x01" +                 # num_headers = 1
      "\xA0\x3c" +                 # UNRECOGNIZED HEADER CODE
      "\x00\x0241\x00" +           #   41
      ""
    assert_raise(Net::AJP13::AJPPacketError) {
      res = Net::AJP13::Response.from_io(StringIO.new(packet))
    }
      
   
    
    # WebDAV response without body
    File.open(File.dirname(__FILE__) + '/data/ajp13response-webdav.1') { |f|
      assert !f.eof?
      res = Net::AJP13::Response.from_io(f)
      assert !f.eof? # because of END_RESPONSE packet

      assert_equal 200, res.status
      assert_equal "200", res.code
      assert_equal "OK", res.reason_phrase
      assert_equal "1,2", res['dav']
      assert_equal "OPTIONS, GET, HEAD, POST, DELETE, TRACE, PROPPATCH, COPY, MOVE, LOCK, UNLOCK, PROPFIND", res['ALLOW']
      assert_equal "DAV", res['MS-Author-Via']
      assert_equal 0, res.content_length
      assert_nil res['no-such-header']
      assert_nil res.body
      assert_nil res.body_stream
    }


    # WebDAV response with body
    File.open(File.dirname(__FILE__) + '/data/ajp13response-webdav.2') { |f|
      assert !f.eof?
      res = Net::AJP13::Response.from_io(f)
      assert !f.eof? # because of BODY_CHUNK packets and END_RESPONSE packet.

      assert_equal 207, res.status
      assert_equal 'Multi-Status', res.message
      assert_equal 'text/xml;charset=UTF-8', res['content-type']
      assert_equal '390', res['content-length']
      assert_equal 390, res.content_length
      assert_nil res['no-such-header']
      assert_nil res.body
      assert_nil res.body_stream
      #assert_equal %Q(<?xml version="1.0" encoding="utf-8" ?>\n<multistatus xmlns="DAV:"><response><href>/webdav/</href>\n<propstat><prop><resourcetype><collection/></resourcetype>\n</prop>\n<status>HTTP/1.1 200 OK</status>\n</propstat>\n<propstat><prop><getcontentlength/><getlastmodified/><executable/><checked-in/><checked-out/></prop>\n<status>HTTP/1.1 404 Not Found</status>\n</propstat>\n</response>\n</multistatus>\n), res.body
    }
  end


  def test_message
    res = Net::AJP13::Response.new(500, :reason_phrase => 'Internal Servlet Container Error :P')
    assert_equal "Internal Servlet Container Error :P", res.message
    assert_equal 500, res.status
    assert_equal "500", res.code
  end

  def test_body
    assert_nil @res.body
    @res.body = "test body"
    assert_equal "test body", @res.body
  end

  def test_body_stream
    assert_nil @res.body
    assert_nil @res.body_stream
    @res.body_stream = io = StringIO.new('test body stream')
    assert_same io, @res.body_stream
    assert_nil @res.body
  end

  def test_send_to
    res = Net::AJP13::Response.new(200, :reason_phrase => 'Yeah!')
    res['content-length'] = '30'

    io = StringIO.new
    res.send_to(io)
    io.rewind
    assert_equal "" +
      "\x41\x42\x00\x14" +         # "AB" length
      "\x04" +                     # SEND_HEADERS
      "\x00\xC8\x00\x05Yeah!\x00" +# 200 Yeah!
      "\x00\x01" +                 # num_headers = 1
      "\xA0\x03" +                 # Content-Length
      "\x00\x0230\x00" +           #   30
      "",
      io.read
  end

  def test_send_to_and_from_io
    res = Net::AJP13::Response.new(500, :reason_phrase => 'Something in the Servlet is wrong')
    res['content-length'] = '50'
    res['X-Framework'] = 'No such Framework T_T'
    res['ConTent-tYpe'] = 'text/html; charset=BIG-5'
    res['Content-Language'] = 'zh-CN'
    res['Servlet-Engine'] = 'No such engine :P'

    io = StringIO.new
    res.send_to(io)
    io.rewind

    assert !io.eof?
    res = Net::AJP13::Response.from_io(io)
    assert io.eof?
    assert_equal 500, res.status
    assert_equal '500', res.code
    assert_equal '50', res['Content-Length']
    assert_equal 50, res.content_length
    assert_equal 'zh-CN', res['Content-Language']
    assert_equal 'text/html; charset=BIG-5', res['Content-Type']
    assert_equal 'No such engine :P', res['Servlet-Engine']
    assert_equal 'No such Framework T_T', res['X-Framework']
    assert_nil res['No-Such-Header']
  end
end

