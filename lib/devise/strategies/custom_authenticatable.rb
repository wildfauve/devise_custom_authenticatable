require 'devise/strategies/authenticatable'

module Devise::Strategies
  # Strategy for delegating authentication logic to custom model's method
  class CustomAuthenticatable < Authenticatable

    def authenticate!
      resource = find_resource

      if resource && resource.respond_to?(:valid_for_custom_authentication?)
        try_strategy(resource, nil)
      else
        auth = mapping.to.initial_authentication(authentication_hash, password)
        resource = find_resource
        try_strategy(resource, auth)
      end

      # return pass unless resource.respond_to?(:valid_for_custom_authentication?)

    end

    def find_resource
      valid_for_params_auth? && valid_password? && mapping.to.find_for_authentication(authentication_hash)
    end

    def try_strategy(resource, auth)
      catch(:skip_custom_strategies) do
        if validate(resource){ resource.valid_for_custom_authentication?(password, auth) }
          resource.after_custom_authentication
          success!(resource)
        end
      end
    end
  end

end

Warden::Strategies.add(:custom_authenticatable, Devise::Strategies::CustomAuthenticatable)
