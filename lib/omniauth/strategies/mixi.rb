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
        :parse => :json,
        :mode => :query,
        :param_name => 'oauth_token',
        :header_format => "OAuth %s"
      }

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

      def raw_info
        @raw_info ||= MultiJson.decode(access_token.get("/2/people/@me/@self?oauth_token=#{access_token.token}").body)
        @raw_info
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
