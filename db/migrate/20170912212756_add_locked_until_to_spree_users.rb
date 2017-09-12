class AddLockedUntilToSpreeUsers < ActiveRecord::Migration
  def change
    add_column :spree_users, :locked_until, :datetime
  end
end
