require 'test/unit'
require 'stringio'
require File.dirname(__FILE__) + '/../../lib/net/ajp13'

class Net::AJP13::RequestTest < Test::Unit::TestCase
  def setup
    @req = Net::AJP13::Request.new('/')
  end
  def test_new
    assert_kind_of Net::AJP13::Request, @req
    assert_equal '/', @req.path

    req_with_another_path = Net::AJP13::Request.new('/path/to/somewhere')
    assert_equal '/path/to/somewhere', req_with_another_path.path
  end

  def test_header
    assert_nil @req['accept-language']
    assert_nil @req['content-type']
    assert_nil @req['content-length']
    
    @req['accept-laguage'] = 'ja,en_US,en'
    assert_equal 'ja,en_US,en', @req['accept-laguage']
    @req['AcCePt-lAgUaGe'] = 'fr,de,es'
    assert_equal 'fr,de,es', @req['accept-laguage']
  end

  def test_attribute
    assert_nil @req.get_attributes('query_string')
    assert_nil @req.get_attributes('something-unrecognized')

    @req.set_attribute('QUERY_STRING', "a=1&b=c")
    assert_equal ["a=1&b=c"], @req.get_attributes('qUeRy_StRiNg')
    
    @req.add_attribute('something-unrecognized', 'abcde')
    @req.add_attribute('something-unrecognized', 'fghij')
    assert_equal ['abcde', 'fghij'], @req.get_attributes('something-unrecognized')

    @req.set_attribute('something-unrecognized', 'something else')
    assert_equal ['something else'], @req.get_attributes('something-unrecognized')
  end

  def test_new
    get = Net::AJP13::GetRequest.new('/path/to/somewhere', 
                                     'Accept' => 'text/xml')
    assert_equal 'GET', get.method
    assert_equal '/path/to/somewhere', get.path
    assert !get.request_body_permitted?
    assert get.response_body_permitted?
    assert_equal 'text/xml', get['accept']
    assert_same false, get.is_ssl?

    post = Net::AJP13::PostRequest.new('/path/to/somewhere/else',
                                       'Accept' => 'application/x-dvi')
    assert_equal 'POST', post.method
    assert_equal '/path/to/somewhere/else', post.path
    assert post.request_body_permitted?
    assert post.response_body_permitted?
    assert_equal 'application/x-dvi', post['accept']

    head = Net::AJP13::HeadRequest.new('/path/to/yet/another/place',
                                       'Accept' => 'application/x-pdf')
    assert_equal 'HEAD', head.method
    assert_equal '/path/to/yet/another/place', head.path
    assert !head.request_body_permitted?
    assert !head.response_body_permitted?
    assert_equal 'application/x-pdf', head['accept']
  end

  def test_send_to
    req = Net::AJP13::HeadRequest.new('/?q=something&a=1',
                                      'Host' => 'localhost')
    req.protocol = 'HTTP/1.1'
    req.remote_addr = '127.0.0.1'
    req.remote_host = 'localhost'
    req.server_name = 'localhost'
    req.server_port = 80
    io = StringIO.new
    req.send_to(io)
    io.rewind
    assert_equal \
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
     "",
      io.read
  end

  def test_from_io
    packet =
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
      "\x00\x09localhost\x00" +       #   localhost
      "\x05" +                      # QUERY_STRING = 
      "\x00\x0Fq=something&a=1\x00"+#  "q=something&a=1"
      "\xFF" +                      # TERMINATOR
      ""
    io = StringIO.new(packet)
    assert !io.eof?
    req = Net::AJP13::Request.from_io(io)
    assert io.eof?
    assert_equal "HEAD", req.method
    assert_equal "/", req.path
    assert_equal "127.0.0.1", req.remote_addr
    assert_equal "localhost", req.remote_host
    assert_equal "localhost", req.server_name
    assert_equal 80, req.server_port
    assert_same false, req.is_ssl?
    assert_equal 1, req.length
    assert_equal "localhost", req['host']

    File.open(File.dirname(__FILE__) + '/data/ajp13request-data.1') {|f|
      assert !f.eof?
      req = Net::AJP13::Request.from_io(f)
      assert f.eof?
      assert_equal "GET", req.method
      assert_equal "HTTP/1.1", req.protocol
      assert_equal "/admin/", req.path
      assert_equal "127.0.0.1", req.remote_addr
      assert_nil req.remote_host
      assert_equal "localhost", req.server_name
      assert_equal 80, req.server_port
      assert_same false, req.is_ssl?
      assert_equal 11, req.length
      req.each do |name, value|
        case name.downcase
        when 'user-agent'
          assert_equal "Opera/8.51 (X11; Linux i686; U; ja)", value
        when 'host'
          assert_equal "localhost", value
        when 'accept'
          assert_equal "text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1", value
        when 'accept-language'
          assert_equal "ja,en;q=0.9", value
        when 'accept-charset'
          assert_equal "shift_jis, utf-8, utf-16, iso-8859-1;q=0.6, *;q=0.1", value
        when 'accept-encoding'
          assert_equal "deflate, gzip, x-gzip, identity, *;q=0", value
        when 'cookie'
          assert_block {
            "JSESSIONID=54104A3A77560CEF8967D263F1A7193" == value or
              "$Version=1" == value
          }
        when 'cache-control'
          assert_equal "no-cache", value
        when 'connection'
          assert_equal "Keep-Alive, TE", value
        when 'TE'
          assert_equal "deflate, gzip, chunked, identity, trailers", value
        when 'content-length'
          assert_equal "0", value
        end
      end
    }
  end
end
