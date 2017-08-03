class AddIpAddressToAuthenticationAttempts < ActiveRecord::Migration
  def change
    add_column :authentication_attempts, :ip_address, :string
  end
end
