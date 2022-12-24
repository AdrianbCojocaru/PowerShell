# base constructors in powershell class inheritance 
class Vehicle {
    [string]$Name
    [int]$Mileage

    Vehicle([string]$VehicleName){
        $this.Name = $VehicleName
    }
}

# class Car inherits from vehicle
class Car : Vehicle {
    # default constructor
    Car(){

    }
    # once we declare this, the default constructor no longer exists by default, it needs to be declared
    Car([string]$CarName, [string]$CarMileage){
        $this.Name = $CarName
        $this.Mileage = $CarMileage
    }
}

[Car]::new()
[Car]::new('Poc')
[Car]::new('Hop', 122)