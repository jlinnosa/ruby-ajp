require 'test/unit'
require 'stringio'
require File.dirname(__FILE__) + "/../../lib/net/ajp13/ajp13cgi.rb"

class Net::AJP13::AJP13CGITest < Test::Unit::TestCase
  def setup
    @encoded_body = 
      "test%5Bfirst%5Fname%5D=foo" +
      "&test%5blast%5Fname%5D=bar+hoge" +
      "&test%5Bemail%5D=foo%2Dbar%40yet%2Eanother%2Edomain%2Etest" +
      "&key+with+SP=huga" +
      "&nanika=unyuu" +
      "&last=%5Ce" +
      ""
    @encoded_body.freeze
    @qs = "last=%5Cufin.%5Ce"

    req = Net::AJP13::PostRequest.new('/path/to/resource')
    req.server_name = 'www.domain.test'
    req.server_port = 8181
    req.is_ssl = true
    req.body_stream = StringIO.new(@encoded_body)
    req['Host'] = 'www.domain.test'
    req['Content-Length'] = @encoded_body.length.to_s
    req['Content-Type'] = 'application/x-www-form-urlencoded'
    req['Content-Language'] = 'ja-JP'
    req['User-Agent'] = @ua = "testcase #{__FILE__}:#{__LINE__}"
    req.set_attribute('QUERY_STRING', @qs)

    @cgi = Net::AJP13::AJP13CGI.new(req)
  end

  def test_at
    assert_equal 'foo', @cgi['test[first_name]']
    assert_equal 'bar hoge', @cgi['test[last_name]']
    assert_equal 'foo-bar@yet.another.domain.test', @cgi['test[email]']
    assert_equal 'huga', @cgi['key with SP']
    assert_equal 'unyuu', @cgi['nanika']
    assert_equal '\e', @cgi['last']
    assert_equal '', @cgi['test[invalid_key]']
    assert_equal '', @cgi['']

    assert_equal '', @cgi['Test[first_name]'] # case sensitive
    assert_equal '', @cgi['test[Last_name]']  # case sensitive
  end

  def test_has_key?
    assert @cgi.has_key?('test[first_name]')
    assert @cgi.has_key?('test[last_name]')
    assert @cgi.has_key?('test[email]')
    assert @cgi.has_key?('key with SP')
    assert !@cgi.has_key?('test[invalid_key]')
    assert !@cgi.has_key?('')

    assert !@cgi.has_key?('Test[first_name]')
  end

  def test_env_table
    assert_equal @encoded_body.length, @cgi.env_table['CONTENT_LENGTH']
    assert_equal 8181, @cgi.env_table['SERVER_PORT']
    assert_equal 'www.domain.test', @cgi.env_table['HTTP_HOST']
    assert_equal @qs, @cgi.env_table['Query_String']
    assert_equal 'application/x-www-form-urlencoded', @cgi.env_table['content_type']
    assert_equal 'AJP/1.3', @cgi.env_table['gateway_interface']
    assert_equal @ua, @cgi.env_table['HTTP_USER_AGENT']
    assert_equal 'ja-JP', @cgi.env_table['HTTP_CONTENT_LANGUAGE']
  end

  def test_params
    assert_equal ['foo'], @cgi.params['test[first_name]']
    assert_equal ['bar hoge'], @cgi.params['test[last_name]']
    assert_equal ['foo-bar@yet.another.domain.test'], @cgi.params['test[email]']
    assert_equal ['huga'], @cgi.params['key with SP']
    assert_equal ['unyuu'], @cgi.params['nanika']
    assert_equal ['\e'], @cgi.params['last']
    assert_equal [], @cgi.params['test[invalid_key]']
    assert_equal [], @cgi.params['']

    assert_equal [], @cgi.params['Test[first_name]'] # case sensitive
    assert_equal [], @cgi.params['test[Last_name]']  # case sensitive
  end

  def test_header_0
    assert_nil @cgi.response
    @cgi.header
    assert_equal 'text/html', @cgi.response['Content-Type']
  end

  def test_header_1
    assert_nil @cgi.response
    @cgi.header('text/plain')
    assert_equal 'text/plain', @cgi.response['Content-Type']
  end

  def test_header
    assert_nil @cgi.response
    @cgi.header(
      "status" => "200 OK",
      "charset" => "EUC-KR"
    )
    assert_equal 'text/html; charset=EUC-KR', @cgi.response['Content-Type']
    assert_equal 'OK', @cgi.response.message
  end
end
