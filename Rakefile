require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'
require 'rake/gempackagetask'

Rake::TestTask.new do |t|
  t.libs << "test" << "lib"
  t.pattern = [ 'test/**/test_ajp13*.rb', 'test/**/more_test_ajp13*.rb' ]
  t.verbose = true
end

Rake::RDocTask.new do |rd|
  rd.rdoc_files.include *['', 'client', 'server'].map{ |n|
    "lib/net/ajp13#{n}.rb"
  }
  rd.title = "Ruby/AJP - An implementation of Apache JServ Protocol 1.3"
end

File.open(File.dirname(__FILE__) + '/ruby-ajp.gemspec') { |f|
  Rake::GemPackageTask.new(eval(f.read)) do |pkg|
    pkg.need_tar_gz = true
    pkg.need_zip = true
  end
}
