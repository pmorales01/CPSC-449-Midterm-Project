# CPSC 449 Midterm Project

## Flask application to demonstrate the following features:

1. JWT Authentication.

2. Password Hashing + Salting.

3. Error handling.

4. File handling.

5. Public view.

## DBMS Prerequisites
* Install [MySQL Workbench](https://www.mysql.com/products/workbench/) and [Xaamp](https://www.apachefriends.org/)
* In Xaamp control panel, run Apache and MySQL services.
![screenshot of xammp control panel, with apache and mysql running](https://github.com/XCaliCatX/CPSC-449-Midterm-Project/blob/mattball/xammp%20control%20panel.png)


* In Workbench, set up a connection with localhost IP, port 3306, and root username.

* To create the 'geekprofile' database & accounts table, execute the following query:
```
CREATE DATABASE IF NOT EXISTS `geekprofile` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
USE `geekprofile`;

CREATE TABLE IF NOT EXISTS `accounts` (
	`id` int(11) NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
    `password` varchar(255) NOT NULL,
    `email` varchar(100) NOT NULL,
    `organisation` varchar(100) NOT NULL,
    `address` varchar(100) NOT NULL,
    `city` varchar(100) NOT NULL,
    `state` varchar(100) NOT NULL,
    `country` varchar(100) NOT NULL,
    `postalcode` varchar(100) NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
```


## Installation

* In the root directory (FlaskPortal), create a python virtual environment
```
python -m venv myenv
```

* Install the project dependencies from requirements.txt

* Once you have activated virtual environment, run:
    ```pip install -r requirements.txt```

* Alternatively, you can run:
    ```python -m pip install -r requirements.txt```

## Setting Up a MySQL Connection in app.py

If the root user has set a password for MySQL (not using a blank default password), update lines 19 and 58 in app.py.

* In line 19, add the actual password after 'root:'
```engine = create_engine('mysql+pymysql://root:actualMySQLpassword@localhost/geekprofile')```

* In line 58, replace the empty string in 'password = ""' with the actual password
```
conn = pymysql.connect(
        host='localhost',
        user='root',
        password = "actualMySQLpassword",
        db='geekprofile',
		cursorclass=pymysql.cursors.DictCursor
        )
```

## Usage

* With dependencies installed and virtual environment activated, navigate to 'geeksprofile'

&ensp;&ensp;Run app.py:


    python app.py



* Create a new user using the registration page. If you're using old users from a database, you may need to delete them
with a query and re-register to login. This applies for the 'admin' user as well.
