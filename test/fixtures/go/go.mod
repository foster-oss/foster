module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/text v0.3.0 // indirect
	github.com/old/lib v1.0.0
)

require github.com/single/dep v0.2.0

replace github.com/old/lib => github.com/new/lib v1.1.0

replace github.com/local/thing => ../thing
