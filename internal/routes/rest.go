package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/latortuga71/GoC2/internal/data"
	"github.com/latortuga71/GoC2/internal/db"
	"github.com/latortuga71/GoC2/internal/log"
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

func StartRestAPI() {
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
		v1.GET("/health", HealthEndpoint)
		v1.GET("/clients", ClientsEndpoint)
		v1.GET("/client/:id", ClientEndpoint)
		v1.GET("/client/:id/tasks", ClientTasks)
		v1.GET("/client/:id/results", ClientResults)
		v1.GET("/operators", OperatorsEndpoint)
	}
	err := router.RunTLS("0.0.0.0:80", "../certs/server.cert", "../certs/server.key")
	log.Log.Fatal().Str("service", "RestAPI").Msgf("%v", err)
}
