#!/usr/bin/ruby
require 'net/ajp13/server'
require 'erb'

class DumpServer < Net::AJP13::Server
  include ERB::Util

  TEMPLATE = DATA.read

  def process_request(req)
    logger.info("Requested from #{req.remote_host}:#{req.remote_addr}")
    res = Net::AJP13::Response.new(200)
    res['Content-Type'] = 'text/html'
    res['Content-Langauge'] = 'en-US'
    res.body = ERB.new(TEMPLATE).result(binding)
    return res
  end
end

serv = DumpServer.new('localhost', 3009)
serv.start


__END__
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN">
<html lang="en-US">
 <head>
  <title>Ruby/AJP example: Dump Server</title>
 </head>
 <body>
  <h1>User request</h1>
  <h2>Request Line</h2>
  <dl>
   <dt>Method</dt><dd><%=h req.method %></dd>
   <dt>Protocol</dt><dd><%=h req.protocol %></dd>
   <dt>Path</dt><dd><%=h req.path%></dd>
  </dl>
  <h2>HTTP headers</h2>
  <dl>
   <% req.each do |name, value| %>
    <dt><%=h name %></dt><dd><%=h value %></dd>
   <% end %>
  </dl>
  <h2>Environments</h2>
  <dl>
   <dt>is_ssl?</dt><dd><%= req.is_ssl? %></dd>
   <dt>remote_addr</dt><dd><%=h req.remote_addr%></dd>
   <dt>remote_host</dt><dd><%=h req.remote_host%></dd>
   <dt>server_name</dt><dd><%=h req.server_name%></dd>
   <dt>server_port</dt><dd><%=h req.server_port%></dd>
  </dl>
  <h2>AJP attributes</h2>
  <dl>
   <% req.each_attribute do |name, value| %>
    <dt><%=h name %></dt><dd><%=h value %></dd>
   <% end %>
  </dl>
  <% if req.body_stream %>
   <% body = req.body_stream.read %>
   <% if %r(\Atext/) =~ req['content-type'] or 
     req['content-type'] == 'application/x-www-form-urlencoded' %>
    <pre><%=h body %></pre>
   <% else %>
    <pre><%=[body].pack('m')%></pre>
   <% end %>
  <% end %>
 </body>
</html>
