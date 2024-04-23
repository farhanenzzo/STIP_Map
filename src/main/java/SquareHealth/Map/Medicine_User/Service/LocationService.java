package SquareHealth.Map.Medicine_User.Service;

import SquareHealth.Map.Medicine_User.Domain.Location;
import SquareHealth.Map.Medicine_User.Repository.LocationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class LocationService {

    @Autowired
    private LocationRepository locationRepository;

    public List<Location> fetchAllLocations() {
        return locationRepository.findAll();
    }

    public Optional<Location> fetchLocationById(long locationId) {
        return locationRepository.findById(locationId);
    }
}
