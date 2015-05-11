#!/usr/bin/ruby

require 'net/ajp13/server'

# This server always returns "Hello, World!"
class HelloServer < Net::AJP13::Server
  def process_request(req)
    logger.info("Requested from #{req.remote_host}:#{req.remote_addr}")
    res = Net::AJP13::Response.new(200)
    res['Content-Type'] = 'text/plain'
    res.body = 'Hello, World!'

    return res
  end
end

serv = HelloServer.new('localhost', 3009)
serv.start
