    package co.app.repository;

    import java.util.List;

    import org.springframework.data.jpa.repository.JpaRepository;
    import org.springframework.stereotype.Repository;

    import co.app.models.entity.RolEntity;
    import co.app.models.entity.RolEnum;

    @Repository
    public interface RolRepository extends JpaRepository<RolEntity, Long> {

        List<RolEntity> findRolEntitiesByRolEnumIn(List<RolEnum> roleEnums);
    }
