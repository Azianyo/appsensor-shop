class CreateAuthenticationAttempts < ActiveRecord::Migration
  def change
    create_table :authentication_attempts do |t|
      t.string :session_id
      t.string :username
      t.boolean :is_successful
    end
  end
end
