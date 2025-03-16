# Natas

## Level 0
You can find the password for level 1 somewhere on the page. 

### Solution
View the page source to find the password for level 1 in a HTML comment. 

## Level 1
You can find the password for level 2 somewhere on the page. But right clicking has been disavbed. 

### Solution 
Download the page and view the source in a text editor. 

## Level 2
There is nothing on this page....

### Solution
Well, not quite nothing. If we view the page source we can find that there is an image, `pixel.png`. Clicking on the image source link in the page source view in Chrome opens the image in a new tab. From the URL we can see that the image is in a firectory on the natas2 server called `files`. Could there be anything else in the folder? Sites can be configured to prevent directory browsing, but in the case of natas 2 this isn't true. If we remove `pixel.png` from the URL we get a directory listing and a file curiously named `users.txt`. Opening this file presents us with a list of usernames and passwords, one of them being natas3. 



