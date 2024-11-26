## Step 1: Download the source code from GitHub from the below link:



## Step 2:  If you do not have Python 3 installed then download  Python 3 or above from the below link :


https://www.python.org/downloads/


## 3 Step 3: Navigate to the BlackHat directory 

## Step 4: Open a command prompt in the BlackHat directory


Step 5: Create a Python virtual environment 


How does a virtual environment work?

We use a module named virtualenv which is a tool to create isolated Python environments. virtualenv creates a folder that contains all the necessary executables to use the packages that a Python project would need.

Installing virtualenv

$ pip install virtualenv

Test your installation:

$ virtualenv --version

Using virtualenv, You can create a virtualenv using the following command:

$ virtualenv my_name

After running this command, a directory named my_name will be created. This is the directory that contains all the necessary executables to use the packages that a Python project would need. This is where Python packages will be installed. If you want to specify the Python interpreter of your choice, for example, Python 3, it can be done using the following command:

$ virtualenv -p /usr/bin/python3 virtualenv_name

To activate the virtual environment using Windows command prompt change the directory to your virtual env 

$ cd <envname>
$ Scripts\activate 
$ source virtualenv_name/bin/activate


geeksforgeeks.org/python-virtual-environment/


## Step 6: Download the required packages using the below command

$ pip install -r requirements.txt 


## Database Connection

## Step 7: Download MongoDB from the below link:

https://www.mongodb.com/try/download/community-kubernetes-operator

## Step 8: Open MongoDB Compass and create a new connection and click connect
![image](https://github.com/user-attachments/assets/9b1a883e-85f9-4b6b-8e64-395b550319ea)




Create a Database named “BLACKHAT”

![image](https://github.com/user-attachments/assets/66b904db-2caa-4efc-bf6f-389e7a06ce59)

 

Create 2 collections named “ACCOUNTS” and “REPORTS”:


![image](https://github.com/user-attachments/assets/6fd13569-9356-4f1d-b0e8-b613976b1761)


Add 1 dummy data for the database to start functioning:

![image](https://github.com/user-attachments/assets/41d01a3b-42e1-403a-ae9f-790932bc3519)


## Step 9: Now navigate to the terminal and run the following command.


 $ python run app.py
Or 

$ python3 run app.py

![image](https://github.com/user-attachments/assets/f09363fd-6957-4046-9390-f8e190a0ce70)


## Step 10: Now go to http://127.0.0.1:5000 in any browser

![image](https://github.com/user-attachments/assets/633c838c-0aed-48bf-b419-ea6071c6a6c0)


