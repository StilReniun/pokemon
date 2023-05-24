package com.example.pokemon.services;

import com.example.pokemon.model.Fire;
import com.example.pokemon.repository.FireRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import javax.transaction.Transactional;

@Service
@Transactional
public class FireServices {
    @Autowired
    private FireRepository  repositorio;
    public FireServices(){
    }


    public List<Fire> buscarTodo() {
        return (List<Fire>) repositorio.findAll();
    }

    public Fire actualizar(Fire fireActualizar) {

        Fire fireActual = repositorio.findById(fireActualizar.getIdPokemon()).get();

        //peliculaActual.setIdPelicula(peliculaActualizar.getIdPelicula());
        fireActual.setNombre(fireActualizar.getNombre());
        fireActual.setImg(fireActualizar.getImg());
        fireActual.setClase(fireActualizar.getClase());
        fireActual.setRegion(fireActualizar.getRegion());
        fireActual.setCategoria(fireActualizar.getCategoria());
        fireActual.setAtaque(fireActualizar.getAtaque());
        fireActual.setVida(fireActualizar.getVida());
        Fire fireActualizado = repositorio.save(fireActual); // registra en base de datos
        return fireActualizado;
    }

    public Fire crear(Fire fire) {
        return repositorio.save(fire);
    }

    public Fire buscarPorId(Integer id) {
        return repositorio.findById(id).get();
    }

    public void borrarPorId(Integer id) {
        repositorio.deleteById(id);
    }
}
