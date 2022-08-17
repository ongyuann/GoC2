package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/latortuga71/GoC2/internal/data"
	"github.com/latortuga71/GoC2/internal/db"
	"github.com/latortuga71/GoC2/internal/log"
	"github.com/latortuga71/GoC2/internal/server"
)

func LogRequest(c *gin.Context) {
	ipStr := c.RemoteIP()
	method := c.Request.Method
	path := c.FullPath()
	log.Log.Info().Str("service", "RestAPI").Msgf("%s %s Request From %s", method, path, ipStr)
}

func ClientResults(c *gin.Context) {
	LogRequest(c)
	id := c.Param("id")
	for key, client := range db.ClientsDatabase.Database {
		if key == id {
			c.JSON(http.StatusOK, client.Results)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "Client not Found."})
}

func ClientTasks(c *gin.Context) {
	LogRequest(c)
	id := c.Param("id")
	for key, client := range db.ClientsDatabase.Database {
		if key == id {
			c.JSON(http.StatusOK, client.Tasks)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "Client not Found."})
}

func ClientEndpoint(c *gin.Context) {
	LogRequest(c)
	id := c.Param("id")
	for key, client := range db.ClientsDatabase.Database {
		if key == id {
			c.JSON(http.StatusOK, client)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "Client not Found."})
}

func ClientsEndpoint(c *gin.Context) {
	LogRequest(c)
	better := make(map[string]data.Client)
	// hack to remove tasks and results.
	for _, x := range db.ClientsDatabase.Database {
		x.Tasks = nil
		x.Results = nil
		//x.RsaPrivateKey = nil
		x.RsaPublicKey = nil
		better[x.ClientId] = x
	}
	c.JSON(200, better)
}

func HealthEndpoint(c *gin.Context) {
	LogRequest(c)
	c.JSON(200, gin.H{
		"Status": "OK",
	})
}

func OperatorsEndpoint(c *gin.Context) {
	LogRequest(c)
	c.JSON(200, db.OperatorsDatabase.Database)
}

func verifyListener(l *data.Listener) error {
	if l.Listener > 1 {
		return errors.New("Invalid Listener Type")
	}
	return nil
}

func DeleteListenerEndpoint(c *gin.Context) {
	LogRequest(c)
	port := c.Param("port")
	// code to delete a listener
	if !db.ListenerDatabase.DeleteListener(port) {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Listener could not be deleted"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"Status": "Deleted Listener"})
	server.ServerBroadCastMessage(fmt.Sprintf("Deleted Listener On Port %s", port))
}

func CreateListenerEndpoint(c *gin.Context) {
	LogRequest(c)
	listenerPayload := &data.Listener{}
	err := c.BindJSON(listenerPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Invalid Json"})
		return
	}
	err = verifyListener(listenerPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Listener type invalid"})
		return
	}
	// code to startup a new listener.
	if !db.ListenerDatabase.AddListener(listenerPayload.Label, listenerPayload.Port, listenerPayload.Listener) {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Listener already active."})
		return
	}
	// pass channel so we can listen on it. for shutdown
	if listenerPayload.Listener == data.WebsocketListener {
		go StartWebSocketListener(listenerPayload.Port, db.ListenerDatabase.Database[listenerPayload.Port].ShutdownChannel)
		c.JSON(http.StatusCreated, gin.H{"Status": "Created WebSocketListener"})
		return
	}
	if listenerPayload.Listener == data.HTTPSListener {
		go StartHttpsListener(listenerPayload.Port, db.ListenerDatabase.Database[listenerPayload.Port].ShutdownChannel)
		c.JSON(http.StatusCreated, gin.H{"Status": "TODO Created HTTPS Listener"})
		return
	}

}

func GetListenerEndpoint(c *gin.Context) {
	LogRequest(c)
	c.JSON(200, db.ListenerDatabase.Database)
}

func StartRestAPI(port string) {
	if !DebugMode {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	about := router.Group("/about")
	{
		about.POST("/contact", DistributeClientCertificate)
	}
	v1 := router.Group("/v1")
	{
		v1.DELETE("/listener/:port", DeleteListenerEndpoint)
		v1.GET("/listeners", GetListenerEndpoint)
		v1.POST("/listeners", CreateListenerEndpoint)
		v1.GET("/health", HealthEndpoint)
		v1.GET("/clients", ClientsEndpoint)
		v1.GET("/client/:id", ClientEndpoint)
		v1.GET("/client/:id/tasks", ClientTasks)
		v1.GET("/client/:id/results", ClientResults)
		v1.GET("/operators", OperatorsEndpoint)
	}
	err := router.RunTLS(fmt.Sprintf("0.0.0.0:%s", port), "../certs/server.cert", "../certs/server.key")
	log.Log.Fatal().Str("service", "RestAPI").Msgf("%v", err)
}

///// HTTP LISTENERS

func LogHTTPSListenerRequest(c *gin.Context) {
	ipStr := c.RemoteIP()
	method := c.Request.Method
	path := c.FullPath()
	log.Log.Info().Str("service", "HTTPSListener").Msgf("%s %s Request From %s", method, path, ipStr)
}

func ListenerHandleCheckIn(c *gin.Context) {
	clientUUID := data.GenerateUUID()
	msgPayload := &data.Message{}
	authHeader := c.GetHeader("authorization")
	if authHeader != server.ServerSharedSecret {
		log.Log.Info().Msgf("Invalid secret provided for https checkin %s", authHeader)
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	err := c.BindJSON(msgPayload)
	if err != nil {
		log.Log.Info().Msg("Invalid client payload provided for https checkin")
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	msg := server.ServerHandleCheckInHTTPS(clientUUID, msgPayload.ToBytes())
	if msg == nil {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed Check Debug Log"})
		return
	}
	c.JSON(http.StatusOK, msg)
	return
}

func ListenerHandleResults(c *gin.Context) {
	resultsArray := make([]data.Message, 0)
	authHeader := c.GetHeader("authorization")
	fmt.Println(authHeader)
	if authHeader != server.ServerSharedSecret {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	idHeader := c.GetHeader("id")
	fmt.Println(idHeader)
	if idHeader == "" {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	err := c.BindJSON(&resultsArray)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	for r := 0; r < len(resultsArray); r++ {
		server.ServerHandleTaskResult(idHeader, resultsArray[r].ToBytes())
	}
	c.JSON(http.StatusOK, gin.H{"Status": "OK"})
	return
}

func ListenerHandleGetTasks(c *gin.Context) {
	authHeader := c.GetHeader("authorization")
	fmt.Println(authHeader)
	if authHeader != server.ServerSharedSecret {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	idHeader := c.GetHeader("id")
	fmt.Println(idHeader)
	if idHeader == "" {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	if _, ok := db.ClientsDatabase.Database[idHeader]; !ok {
		c.JSON(http.StatusNotFound, gin.H{"Status": "Not Found"})
		return
	}
	db.ClientsDatabase.UpdateClientLastSeen(idHeader)
	c.JSON(http.StatusOK, db.ClientsDatabase.ClientGetAvailableTasks(idHeader))
}

func StartHttpsListener(port string, shutdownChannel chan int) {
	if !DebugMode {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	router.GET("/tasks", ListenerHandleGetTasks)
	router.POST("/results", ListenerHandleResults)
	router.POST("/login", ListenerHandleCheckIn)
	httpServer := http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()
	go httpServer.ListenAndServeTLS("../certs/server.cert", "../certs/server.key")
	msg := fmt.Sprintf("Started HTTPS listener on %s ", port)
	msgDown := fmt.Sprintf("Shutting down HTTPS listener on %s ", port)
	log.Log.Info().Msg(msg)
	server.ServerBroadCastMessage(msg)
	<-shutdownChannel
	log.Log.Info().Msg(msgDown)
	httpServer.Shutdown(ctxShutDown)
	shutdownChannel <- 1
}
