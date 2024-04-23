package SquareHealth.Map.Medicine_User.Controller;

import SquareHealth.Map.Medicine_User.Domain.Location;
import SquareHealth.Map.Medicine_User.Service.LocationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping()
public class LocationController {

    @Autowired
    private LocationService locationService;

    @GetMapping("/map")
    public List<Location> getAllLocation() {
        return locationService.fetchAllLocations();
    }

    @GetMapping("/map/{locationId}")
    public Optional<Location> getLocationById(@PathVariable long locationId) {
        return locationService.fetchLocationById(locationId);
    }
}
