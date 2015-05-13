#!/usr/bin/ruby

require 'net/ajp13/client'

Net::AJP13::Client.start('localhost',3009) do |client|
  puts client.get('/index.jsp').body
end

