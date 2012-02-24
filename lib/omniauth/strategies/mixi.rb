require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Mixi < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site => 'https://secure.mixi-platform.com',
        :authorize_url => 'https://mixi.jp/connect_authorize.pl',
        :token_url => 'https://secure.mixi-platform.com/2/token',
        :ssl => {:ca_path => "/etc/ssl/certs"}
      }

      option :authorize_params, {
        :scope => 'r_profile w_pagefeed',
        :display => 'pc',
        :response_type => 'code'
      }

      option :token_params, {
        :parse => :json
      }

      option :profile_request_params, {
        :thumbnailPrivacy => 'everyone'
      }

      option :profile_request_options, [ :thumbnailPrivacy ]

      uid { raw_info['entry']['id']}

      info do
        prune!({
          'name' => raw_info['entry']['displayName'],
          'image' => raw_info['entry']['thumbnailUrl'],
          'urls' => {
            'Mixi' => raw_info['entry']['profileUrl'],
          }
        })
      end

      extra do
        prune!({
          'raw_info' => raw_info
        })
      end

      def callback_phase
        options[:grant_type] ||= 'client_credentials'
        super
      end

      def profile_request_params
        options.profile_request_params.merge(options.profile_request_options.inject({}){|h,k| h[k.to_sym] = options[k] if options[k]; h})
      end

      def raw_info
        @raw_info ||= access_token.get('/2/people/@me/@self', :params => profile_request_params).parsed
      end

      def build_access_token
        super.tap do |token|
          token.options.merge!(:mode => :header,
                               :param_name => 'oauth_token',
                               :header_format => "OAuth %s")
        end
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end
    end
  end
end
