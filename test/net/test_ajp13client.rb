require 'test/unit'
require File.dirname(__FILE__) + '/../../lib/net/ajp13/client'

class Net::AJP13::ClientTest < Test::Unit::TestCase
  def setup
    begin
      sock = TCPSocket.new('localhost', 8009)
    rescue
      warn "#{__FILE__}:#{__LINE__}: This test case requires that" +
        " a servlet container is listening localhost:8009." +
	" Almost all tests in #{self.class} will be ignored."
      @ignored = true
    else
      sock.close
    end
    @c = Net::AJP13::Client.new('localhost')
  end

  def test_new
    assert_equal 'localhost', @c.address
    assert_equal 8009, @c.port
    assert !@c.started?
    assert !@c.assigned?
    assert !@c.idle?
    assert_nil @c.state
    assert_kind_of Integer, @c.open_timeout
    assert_kind_of Integer, @c.read_timeout
    assert_kind_of Integer, @c.write_timeout

    c = Net::AJP13::Client.new('localhost', 9008)
    assert_equal 'localhost', c.address
    assert_equal 9008, c.port
    assert !c.started?
    assert !c.assigned?
    assert !c.idle?
    assert_nil c.state

    # Nothing raised because client does not try to connect until #start()ing.
    assert_nothing_raised { 
      c = Net::AJP13::Client.new('test.invalid') # unresolvable by RFC2026
    }
    assert_equal 'test.invalid', c.address
    assert_equal 8009, c.port
    assert !c.started?
    assert !c.assigned?
    assert !c.idle?
    assert_nil c.state
  end

  def test_start_finish
    return if @ignored

    assert_nothing_raised { @c.start }
    assert @c.started?
    assert @c.idle?
    assert !@c.assigned?
    assert_equal :idle, @c.state

    assert_nothing_raised { @c.finish }
    assert !@c.started?
    assert !@c.assigned?
    assert !@c.idle?
    assert_nil @c.state
  end

  def test_finish
    assert_raise(Net::AJP13::AJPStateError) { @c.finish }
  end

  def test_start_with_block
    return if @ignored

    expected = Object.new
    retval = @c.start { |c|
      assert_same @c, c
      assert @c.started?
      assert @c.idle?
      assert !@c.assigned?
      assert_equal :idle, @c.state

      expected
    }
    assert_same expected, retval

    assert !@c.started?
    assert !@c.assigned?
    assert !@c.idle?
    assert_nil @c.state
  end

  def test_start_with_block_on_raised
    return if @ignored

    assert_raise(RuntimeError, 'Error on connection opened') {
      @c.start { |c|
        assert_same @c, c
         assert @c.started?
	 assert @c.idle?
	 assert !@c.assigned?
	 assert_equal :idle, @c.state

         raise 'Error on connection opened'
      }
    }
    assert !@c.started?
    assert !@c.assigned?
    assert !@c.idle?
    assert_nil @c.state
  end

  def test_finish_only_once
    return if @ignored

    class << @c
      alias :orig_finish :finish
      def finish
        @finish_count ||= 0
	@finish_count += 1
	orig_finish
      end
      attr :finish_count
    end
    @c.start { |c|
      assert @c.started?
      assert @c.idle?
      assert !@c.assigned?

      c.finish

      assert !@c.started?
      assert !@c.idle?
      assert !@c.assigned?
    }
    assert_equal 1, @c.finish_count
    assert !@c.started?
    assert !@c.idle?
    assert !@c.assigned?
  end


  def test_restart
    return if @ignored

    class << @c
      alias :orig_finish :finish
      def finish
        @finish_count ||= 0
	@finish_count += 1
	orig_finish
      end
      attr :finish_count
    end
    @c.start { |c|
      assert @c.started?
      assert @c.idle?
      assert !@c.assigned?

      c.finish

      assert !@c.started?
      assert !@c.idle?
      assert !@c.assigned?

      c.start

      assert @c.started?
      assert @c.idle?
      assert !@c.assigned?
    }
    assert_equal 2, @c.finish_count

    assert !@c.started?
    assert !@c.assigned?
    assert !@c.idle?
  end

  def test_class_start
    return if @ignored

    c = Net::AJP13::Client.start('localhost')
    begin
      assert_equal 'localhost', c.address
      assert_equal 8009, c.port
      assert c.started?
      assert c.idle?
    return if @ignored
    return if @ignored


      assert !c.assigned?
      assert_equal :idle, c.state
    ensure
      c.finish
    end
  end

  def test_class_start_with_block
    return if @ignored

    created_conn = nil
    expected = Object.new
    retval = Net::AJP13::Client.start('localhost') { |c|
      assert_equal 'localhost', c.address
      assert_equal 8009, c.port
      assert c.started?
      assert c.idle?
      assert !c.assigned?
      assert_equal :idle, c.state

      created_conn = c
      expected
    }
    assert_same expected, retval

    assert !created_conn.started?
    assert !created_conn.assigned?
    assert !created_conn.idle?
    assert_nil created_conn.state
  end

  def test_ask_to_shutdown
    return if @ignored

    @c.start { |conn|
      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?

      assert_nothing_raised { conn.ask_to_shutdown }

      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
    }
  end

  def test_ping
    return if @ignored

    @c.start { |conn|
      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
      
      conn.ping

      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
    }
  end

  def test_request
    return if @ignored

    req = Object.new
    class << req
      def send_to(io)
        io.write "" +
	  "\x12\x34\x00\x35" +       # signature length
          "\x02\x03" +               # FORWARD_REQUEST HEAD
	  "\x00\x08HTTP/1.0\x00" +   # protocol: HTTP/1.0
	  "\x00\x01/\x00" +          # req_uri:  /
	  "\x00\x09127.0.0.1\x00" +  # remote_addr: 127.0.0.1
	  "\xFF\xFF" +               # remote_host: nil
	  "\xFF\xFF" +               # server_name: nil
	  "\x00\x50" +               # server_port: 80
	  "\x00" +                   # is_ssl : false
	  "\x00\x01" +               # num_headers = 1
	  "\xA0\x0B" +               #  Host:
	  "\x00\x09localhost\x00" +  #   localhost
	  "\xFF"                     # TERMINATOR
      end
      def method_missing(*args)
        nil
      end
    end

    @c.start { |conn|
      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
      
      res = conn.request(req)

      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
    }
  end

  def test_request_with_body
    return if @ignored

    req = Net::AJP13::PostRequest.new('/index.jsp')
    req.body = (['a=1'] * 10 * 1024).join('&')
    @c.start { |conn|
      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?

      res = conn.request(req)

      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
    }
  end

  def test_request_with_block
    return if @ignored

    req = Net::AJP13::PostRequest.new('/index.jsp')
    req.body = (['a=1'] * 10 * 1024).join('&')
    @c.start { |conn|
      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?

      body = ''
      res = conn.request(req){ |frag|
        assert conn.started?
	assert !conn.idle?
	assert conn.assigned?
	assert_kind_of String, frag
	body << frag
      }
      assert_nil res.body
      assert body.length > 0

      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
    }
  end

  def test_get
    return if @ignored

    @c.start { |conn|
      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
      
      res = conn.get('/', 'User-Agent' => "Ruby/AJP #{__FILE__}")
      assert res.body.length > 0

      assert conn.started?
      assert conn.idle?
      assert !conn.assigned?
    }
  end
end
