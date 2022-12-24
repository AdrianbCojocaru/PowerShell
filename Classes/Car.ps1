class Car {
    [string]$Color
    [string]$Name
    [string]$Manufacturer
    [string]$Model
    [int]$Length
    [int]$Width
    [int]$Hight
    [int]$Mileage
    
    # Methoods
    [void]Drive([int]$NumberOfMiles){
        $this.Mileage += $NumberOfMiles
    }

    # Constructors
    Car(){
        
    }

    Car([int]$Mileage ){
        $this.Mileage = $Mileage
    }

    Car([string]$Name, [int]$Mileage ){
        $this.Name = $Name
        $this.Mileage = $Mileage
    }

}

$Car1 = [Car]::new()
$Car2 = [Car]::new('Alexa', 14276)
$Car2.Drive(1)