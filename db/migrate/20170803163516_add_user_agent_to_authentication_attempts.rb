class AddUserAgentToAuthenticationAttempts < ActiveRecord::Migration
  def change
    add_column :authentication_attempts, :user_agent, :text
  end
end
