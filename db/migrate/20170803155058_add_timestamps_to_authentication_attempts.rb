class AddTimestampsToAuthenticationAttempts < ActiveRecord::Migration
  def change
    add_column(:authentication_attempts, :created_at, :datetime)
    add_column(:authentication_attempts, :updated_at, :datetime)
  end
end
