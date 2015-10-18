require_relative 'tools'

class ApacheGelf < FPM::Cookery::Recipe
  include Tools

  description 'Apache2 GELF log module'

  name     'libapache2-mod-gelf'
  version  data.version
  revision data.revision
  homepage data.homepage
  arch     'amd64'

  maintainer data.maintainer
  vendor     data.vendor
  license    data.license

  source 'file:///apache-gelf/src'

  platforms [:ubuntu] do
    section 'net'
    depends 'apache2', 'libjson-c2', 'zlib1g'
    build_depends 'libjson-c-dev', 'zlib1g-dev'

    config_files '/etc/apache2/mods-available/log_gelf.load',
                 '/etc/apache2/mods-available/log_gelf.conf'
  end

  def build
    FileUtils.touch(File.join(builddir, '.deps')) 
  end

  def install
    case FPM::Cookery::Facts.platform
    when :ubuntu, :debian
      etc('apache2/mods-available').install osfile('log_gelf.load'), 'log_gelf.load'
      etc('apache2/mods-available').install osfile('log_gelf.conf'), 'log_gelf.conf'
    end

    make :install, 'DESTDIR' => destdir
  end
end
