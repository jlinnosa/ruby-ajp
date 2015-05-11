Gem::Specification.new do |spec|
  spec.name = "ruby-ajp"
  spec.version = "0.2.2"
  spec.required_ruby_version = ">= 1.8.3"
  spec.summary = "An implementation of Apache Jserv Protocol 1.3 in Ruby"
  spec.author = "Yugui"
  spec.email = "yugui@yugui.sakura.ne.jp"
  spec.rubyforge_project = "ruby-ajp"
  spec.files = 
    Dir.glob("lib/**/*.rb") +
    Dir.glob("test/**/test_*.rb") +
    Dir.glob("test/**/data/*") +
    Dir.glob("example/**/*.rb") +
    Dir.glob("NEWS.{en,ja}") + 
    Dir.glob("Install.{en,ja}") + 
    Dir.glob("README.{en,ja}") <<
    "Rakefile" <<
    "ruby-ajp.gemspec" <<
    "setup.rb" <<
    "COPYING"
  spec.files.reject! {|fn| fn.include?('.svn') }
  spec.test_files = [
    'packet', 'request', 'response', 'client', 'server'
  ].map{|x| "test/net/test_ajp13#{x}.rb"}
  spec.has_rdoc = true
end
