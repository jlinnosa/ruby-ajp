#!/usr/bin/ruby

require 'net/ajp13/server'

# This server always raises error
class ErrorServer < Net::AJP13::Server
  def process_request(req)
    raise 'something wrong'
  end
end

serv = ErrorServer.new('localhost', 3009)
serv.start
