# Known Issues
Being a device from 2001, there's obviously bound to be some issues with the current specification, so here are some!

# Email (POP3)
Your server *must* end the mail with a BLANK new line then the period, for example:
```
EML DATA

.
```

If it does not include the blank new-line (Dovecot doesn't!), the Game Boy Color will not accept the mail. The Adapter script should be handling this soon, but for now keep this in mind.


# HTTP
For Pokémon Crystal, any headers will make /cgb/download requests fail (maybe other games?) - to fix this, we run Nginx with more_clear_headers, and remove most headers:


`more_clear_headers Server Date Content-Type Transfer-Encoding;`


Apache can also do this, but both of them will leave some headers (Apache leaves Date, Nginx leaves Connection); again, hopefully the adapter script can help bypass this.

