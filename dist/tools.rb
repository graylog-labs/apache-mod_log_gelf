require 'yaml'

module Tools
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def fact(key)
      Facter.fact(key).value
    rescue NoMethodError
      raise "No fact for: #{key}"
    end

    def os
      os = fact('operatingsystem').downcase

      case os
      when 'centos'
        'el'
      else
        os
      end
    end

    def osrel
       osrel = fact('operatingsystemrelease').downcase

       case os
       when 'debian', 'centos', 'el'
         osrel.split('.').first
       else
         osrel
       end
    end

    def sigar_cleanup(path)
      Dir["#{path}/*"].each do |file|
        unless file.end_with?('.so')
          FileUtils.rm(file)
        end

        if file =~ /freebsd|aix|solaris/
          FileUtils.rm(file)
        end

        if file =~ /(ppc.*|ia64|s390x)-linux/
          FileUtils.rm(file)
        end
      end
    end
  end

  def fact(key)
    self.class.fact(key)
  end

  def os
    self.class.os
  end

  def osrel
    self.class.osrel
  end

  def sigar_cleanup(path)
    self.class.sigar_cleanup(path)
  end

  def osfile(name)
    workdir(File.join('files', FPM::Cookery::Facts.platform.to_s, name))
  end

  def file(name)
    workdir(File.join('files', name))
  end

end

# WOW, monkeypatch!
#
# * Adds data method to recipe
# * Calls after_build_package(output) on recipe if it exists.
module FPM
  module Cookery
    class Recipe
      class RecipeData
        def initialize(recipe)
          @yaml = YAML.load_file(File.expand_path('../data.yml', __FILE__))
          @recipe = recipe
        end

        def version
          data('version')
        end

        def version_major
          data('version_major')
        end

        def revision
          data('revision')
        end

        def source
          data('source')
        end

        def sha256
          data('sha256')
        end

        def homepage
          data('homepage')
        end

        def maintainer
          data('maintainer')
        end

        def vendor
          data('vendor')
        end

        def license
          data('license')
        end

        private

        def data(key)
          data = @yaml['default'].merge(@yaml.fetch(@recipe.name, {}))
          pattern = /#\{(\S+?)\}/

          data[key].gsub(pattern) do |match|
            if match =~ pattern
              if @recipe.respond_to?($1)
                @recipe.public_send($1)
              elsif data.has_key?($1)
                data.fetch($1)
              else
                raise "No replacement for #{$1} found, abort."
              end
            end
          end
        end
      end

      def self.data
        RecipeData.new(self)
      end

      def data
        self.class.data
      end
    end

    class Packager
      def build_package(recipe, config)
        recipe.pkgdir.mkdir
        Dir.chdir(recipe.pkgdir) do
          version = FPM::Cookery::Package::Version.new(recipe, @target, config)
          maintainer = FPM::Cookery::Package::Maintainer.new(recipe, config)

          input = recipe.input(config)

          input.version = version
          input.maintainer = maintainer.to_s
          input.vendor = version.vendor if version.vendor
          input.epoch = version.epoch if version.epoch

          add_scripts(recipe, input)
          #remove_excluded_files(recipe)

          output_class = FPM::Package.types[@target]

          output = input.convert(output_class)

          begin
            output.output(output.to_s)

            if recipe.respond_to?(:after_build_package)
              recipe.after_build_package(output)
            end
          rescue FPM::Package::FileAlreadyExists
            Log.info "Removing existing package file: #{output.to_s}"
            FileUtils.rm_f(output.to_s)
            retry
          ensure
            input.cleanup if input
            output.cleanup if output
            Log.info "Created package: #{File.join(Dir.pwd, output.to_s)}"
          end
        end
      end
    end
  end
end
