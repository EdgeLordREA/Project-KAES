from KAESdatabase import kaes_database, initialize_global_tunnel

initialize_global_tunnel()

db = kaes_database()
#db.create_exam("Sample Exam", "This is a sample exam for testing purposes.")
db.create_question("What is the capital of France?", 1, 5)