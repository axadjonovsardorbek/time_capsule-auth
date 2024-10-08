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

	prod, err := kafka.NewKafkaProducer([]string{"kafka-capsule:9092"})
	us := service.NewUsersService(conn)
	kfk := kafka.NewKafkaConsumerManager()
	broker := []string{"kafka-capsule:9092"}
	kfk.RegisterConsumer(broker, "user", "u", kafka.UserCreateHandler(us))
	
	if err != nil {
		log.Fatal(err)
		return
	}
	
	handler := handler.NewHandler(us, prod)

	roter := api.NewApi(handler)
	log.Println("Server is running on port ", cf.AUTH_PORT)
	if err := roter.Run(cf.AUTH_PORT); err != nil {
		slog.Error("Error:", err)
	}
}
