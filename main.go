package main

import (
	"auth/api"
	"auth/api/handler"
	"auth/config"
	"auth/kafka"
	"auth/service"
	"auth/storage/postgres"
	"log"
	"log/slog"
)

func main() {
	cf := config.Load()

	conn, err := postgres.NewPostgresStorage(cf)

	if err != nil {
		slog.Error("Failed to connect postgres:", err)
	}

	defer conn.Db.Close()

	kafka, err := kafka.NewKafkaProducer([]string{"localhost:9092"})
	if err != nil {
		log.Fatal(err)
		return
	}

	us := service.NewUsersService(conn)
	handler := handler.NewHandler(us, kafka)

	roter := api.NewApi(handler)
	log.Println("Server is running on port ", cf.AUTH_PORT)
	if err := roter.Run(cf.AUTH_PORT); err != nil {
		slog.Error("Error:", err)
	}
}
