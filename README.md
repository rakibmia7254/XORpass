XORpass - Secure Password Manager
=================================

XORpass is a Flask-based password manager application with MongoDB integration. It allows users to securely store their passwords in a MongoDB database, with encryption applied using their own master password. This ensures that the stored passwords are protected and can only be accessed by the owner.

Features
--------

*   User authentication and registration system.
*   Encrypted storage of passwords in the database.
*   Passwords are encrypted using the user's password, ensuring security.
*   Simple and intuitive user interface for managing passwords.

Installation
------------

1.  Clone the repository:
    
    `git clone https://github.com/rakibmia7254/XORpass.git`
    
2.  Install dependencies:
    
    `pip install -r requirements.txt`
    
3.  Configure MongoDB URI:
    
    Update the `MONGO_URI` variable in `app.py` with your MongoDB connection URI.
    
4.  Run the application:
    
    `python app.py`
    
5.  Access the application in your web browser at [http://localhost:5000](http://localhost:5000).

Usage
-----

*   Register for a new account or log in if you already have one.
*   Once logged in, you can add, view, edit, and delete your passwords.
*   All passwords are encrypted using your master password, ensuring security.

Contributing
------------

Contributions are welcome! If you have any suggestions, feature requests, or bug reports, please open an issue or submit a pull request.

License
-------

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Acknowledgements
----------------

*   Flask - [https://flask.palletsprojects.com/](https://flask.palletsprojects.com/)
*   MongoDB - [https://www.mongodb.com/](https://www.mongodb.com/)