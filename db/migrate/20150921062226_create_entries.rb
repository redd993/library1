class CreateEntries < ActiveRecord::Migration
  def change
    create_table :entries do |t|
      t.string :title
      t.integer :isbn
      t.text :notes
      t.integer :user_id

      t.timestamps null: false
    end
  end
end
