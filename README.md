### Agent Checklist
- [ ] Implement Execute-Assembly Functionality
- [ ] Add above to tortuga toolkit
- [ ] Add above to external payloads section if cant be embedded into agent
- [ ] Add Persistence Payload to Payloads section
- [ ] Add More Evasion Payloads to payloads section
- [ ] Add tortuga toolkit functionality to payloads section
- [ ]  Add meowth core agent functionality to payloads section.


### CheckList
- [X] Actually Works.
- [X] ChatServer
- [X] Implement Dynamic mTLS
- [X] Add Exit Option when in client interact menu.
- [X] Move updating last seen into server clean connections function.
- [X] Condense operator api calls.
- [X] Add error handling. USE EXIT TYPE with message to tell client/operator what happened (why no check in?)
- [X] Add flags for server/operator to specify shared secret.
- [X] Add server logging.
- [X] Clean up package global variables.
- [X] Add Client Joined Message to teamchat.
- [X] move ca server to port 80.
- [X] conn writes need mutexes.
- [X] makefile for windows needs to manually string replace global vars in client.go
- [X] generate clients with certs embedded dynamically after server is started. (remove client acquire cert part.)
      seperate binary will read ca certs from disk and then call go build on client using embed package. on certs?
      flag for server hostname?
- [ ] Add Fake pages when accessing anything other than specific routes. (like nginx routing.)
- [ ] Add mTLS to rest api.
- [ ] Write Tests
- [ ] Clean Up Code (make it smaller/more simple) (After Tests)
- [ ] Implement Windows Modules (Port MeowthCore to golang)
- [ ] Add Persistent SQLite Database.