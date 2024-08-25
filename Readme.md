# Week 5: Databases and Web Applications - Bridging the Gap 

Great work last week! You've mastered data manipulation in your Expense Tracker. This week, we'll develop a web application using Node.js, Express, and MySQL to manage personal expenses. The application should provide user authentication and functionalities for adding, viewing, and (optionally) editing/deleting expenses.

## Submission: 
* **Clone** this repo Not ~~Fork~~
* You have been given starter code, use it , modify it as you work on this project
* Test and commit your changes **on this repo**

### Project Setup:
**1.** Create a well-structured Node.js project directory with your server-side code.

**2.** Install required dependencies including express, mysql, body-parser, and a password hashing library (e.g., bcryptjs).

**3.** Configure a connection to your MySQL database.

### Database Schema:
**1.** Create Users table with columns for id (primary key), username (unique), and password (hashed).

**2.** Create an Expenses table with columns for id (primary key), user_id (foreign key referencing Users.id), amount, date, and category.

### User Authentication:
**1.** Implement user registration and login functionalities (covered in previous assignment).

**2.** Securely store passwords using hashing techniques.

### Expense Management:
**1.** Add Expense: Develop a functionality for authenticated users to add new expenses with details like amount, date, and category.

### View Expenses: 
**1.** Allow users to view their past expenses filtered by their user ID.

### (Optional): 
Implement functionalities for authenticated users to edit or delete existing expenses (consider authorization and confirmation steps).

### Security:
**1.** Emphasize secure password storage (hashed, not plain text).
**2.** Consider user authentication and authorization for accessing expense functionalities.

### Deliverables:

**1.** A well-documented Node.js project directory with your server code.

**2.** A clear README.md file explaining project setup, dependencies, functionalities, and instructions to run the application.

**3.** A functional Node.js server demonstrating the required functionalities and interaction with the MySQL database.

### Bonus (Optional)

1.1. Database Server Comparison:  
Create a table comparing the following database server options (focusing on its role as a web application environment): 
* MySQL
* PostgreSQL
* Microsoft SQL Server
* Oracle Database
* Node.js 

**Include details like (Tabulate):**

1. Type (Open-Source/Commercial)
2. Target Audience
3. Key Features
4. Ease of Use

* Upload the table in a document or as a picture onto this repo. 
