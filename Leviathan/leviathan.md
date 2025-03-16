# Leviathan

## Leviathan 0->1

### Solution 
```
ls -la
cd .backup
ls
cat bookmarks.html
```
Way too much text to read, see if we can grep something useful 

```
cat bookmarks.html | grep leviathan
```
Result is a line of text containing the password for leviathan1. 

## Leviathan 1->2
`strings` got me part of the way, but not all the way. Hex dumping revealed some more strings, all of which needed to be used to get the password. 

### Solution
```
sexsecrretgodlove
```