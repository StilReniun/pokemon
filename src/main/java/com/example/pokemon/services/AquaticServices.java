package com.example.pokemon.services;

import com.example.pokemon.model.Aquatic;
import com.example.pokemon.repository.AquaticRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;

@Service
@Transactional
public class AquaticServices {
    @Autowired
    private AquaticRepository repositorio;

    public AquaticServices() {
    }

    public List<Aquatic> buscarTodo() {
        return (List<Aquatic>) repositorio.findAll();
    }

    public Aquatic actualizar(Aquatic aquaticActualizar) {

        Aquatic aquaticActual = repositorio.findById(aquaticActualizar.getIdPokemon()).get();

        //peliculaActual.setIdPelicula(peliculaActualizar.getIdPelicula());
        aquaticActual.setNombre(aquaticActualizar.getNombre());
        aquaticActual.setImg(aquaticActualizar.getImg());
        aquaticActual.setClase(aquaticActualizar.getClase());
        aquaticActual.setRegion(aquaticActualizar.getRegion());
        aquaticActual.setCategoria(aquaticActualizar.getCategoria());
        aquaticActual.setAtaque(aquaticActualizar.getAtaque());
        aquaticActual.setVida(aquaticActualizar.getVida());
        Aquatic aquaticActualizado = repositorio.save(aquaticActual); // registra en base de datos
        return aquaticActualizado;
    }

    public Aquatic crear(Aquatic aquatic) {
        return repositorio.save(aquatic);
    }

    public Aquatic buscarPorId(Integer id) {
        return repositorio.findById(id).get();
    }

    public void borrarPorId(Integer id) {
        repositorio.deleteById(id);
    }
}
