module Rack
  class Attack
    class Fail2Ban
      class << self
        def filter(discriminator, options)
          bantime   = options[:bantime]   or raise ArgumentError, "Must pass bantime option"
          findtime  = options[:findtime]  or raise ArgumentError, "Must pass findtime option"
          maxretry  = options[:maxretry]  or raise ArgumentError, "Must pass maxretry option"
          track = {
            banned_until: false,
            failed_attempts: false
          }.merge(options[:track] || {})

          if banned?(discriminator)
            # Return true for blacklist
            cache.count("#{key_prefix}:count:#{discriminator}", findtime) if track[:failed_attempts]
            true
          elsif yield
            fail!(discriminator, bantime, findtime, maxretry, track)
          end
        end

        def failed_attempts(discriminator, period)
          results = cache.count("#{key_prefix}:count:#{discriminator}", period)
          epoch_time = Time.now.to_i
          key = "#{(epoch_time/period).to_i}:#{key_prefix}:count:#{discriminator}"
          cache.read(key)
        end

        def banned_until(discriminator)
          cache.read("#{key_prefix}:ban:#{discriminator}:banned_until")
        end

        protected
        def key_prefix
          'fail2ban'
        end

        def fail!(discriminator, bantime, findtime, maxretry, track)
          count = cache.count("#{key_prefix}:count:#{discriminator}", findtime)
          if count >= maxretry
            ban!(discriminator, bantime, track)
          end

          true
        end


        private
        def ban!(discriminator, bantime, track)
          cache.write("#{key_prefix}:ban:#{discriminator}", 1, bantime)
          cache.write("#{key_prefix}:ban:#{discriminator}:banned_until", Time.now() + bantime, bantime) if track[:banned_until]
        end

        def banned?(discriminator)
          cache.read("#{key_prefix}:ban:#{discriminator}")
        end

        def cache
          Rack::Attack.cache
        end
      end
    end
  end
end
