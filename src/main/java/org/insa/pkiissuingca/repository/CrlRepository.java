package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.CrlEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CrlRepository extends JpaRepository<CrlEntity, Long> {
    Optional<CrlEntity> findTopByCaSerialNumberAndScopeOrderByCrlNumberDesc(String caSerialNumber, String scope);
    List<CrlEntity> findByCaSerialNumberOrderByCrlNumberDesc(String caSerialNumber);
    List<CrlEntity> findByCaSerialNumber(String caSerialNumber);
}
